<#
.SYNOPSIS
  RV-Remediate.ps1 - apply agreed PERSISTENT fixes, then re-run RV-Validation.ps1 (ASCII only).

.DESCRIPTION
  SAFE BY DEFAULT: without switches it changes NOTHING (backup + validation only).
  Every change is preceded by a backup to <OutDir>\backup-<time>; -Restore <folder> rolls it back.
  -WhatIf shows what would be changed without changing anything.

    -FixAgentConfig            remove from local ossec.conf every <localfile> that also exists in the group
                               shared\agent.conf, and the local <client_buffer> if the group defines one;
                               auto-rollback if the agent does not reconnect in 90 s
    -DisableInvocationLogging  EnableScriptBlockInvocationLogging = 0 (stops 4105/4106; 4104 stays ON)
    -FirewallLogging           LogBlocked = True, log names domainfw/privatefw/publicfw.log (no traffic impact)
    -EnablePublicFirewall      turn ON the firewall in the Public profile (ONLY with server owner approval)

  All read-only checks (agent state, buffer, duplicated channels, 4947, 4104/4105/4106) are done by
  RV-Validation.ps1, which runs at the end. It is taken from the script folder, <OutDir> or downloaded.
  Exit code: validator exit code (0 - all OK, 1 - MISSING), 2 - not Administrator, 3 - config change rolled back.

.EXAMPLE
  .\RV-Remediate.ps1 -FixAgentConfig -DisableInvocationLogging -FirewallLogging -WhatIf
.EXAMPLE
  .\RV-Remediate.ps1 -FixAgentConfig -DisableInvocationLogging -FirewallLogging
.EXAMPLE
  .\RV-Remediate.ps1 -Restore C:\SOC_Audit\backup-20261006_120000
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [switch]$FixAgentConfig,
  [switch]$DisableInvocationLogging,
  [switch]$FirewallLogging,
  [switch]$EnablePublicFirewall,
  # Roll back from a backup folder created by an earlier run
  [string]$Restore,
  [string]$OutDir = 'C:\SOC_Audit',
  # Passed to RV-Validation.ps1
  [string]$AgentName = $env:COMPUTERNAME,
  [ValidateSet('cmd', 'logon', 'service', 'task', 'firewall', 'share', 'user', 'powershell')][string[]]$Only = @(),
  # Do not run RV-Validation.ps1 at the end
  [switch]$NoValidation,
  # Where to download RV-Validation.ps1 from if it is not found locally
  [string]$ValidatorUrl = 'https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1'
)
$ErrorActionPreference = 'Continue'

function Step { param($t) Write-Host ("`n[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $t) -ForegroundColor Cyan }
function Warn { param($t) Write-Host "  $t" -ForegroundColor Yellow }
function Exit-Script {
  param([int]$Code)
  if ($MyInvocation.PSCommandPath) { exit $Code }
  $global:LASTEXITCODE = $Code
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'Run this script as Administrator.' -ForegroundColor Red
  Exit-Script 2
  return
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$txt = Join-Path $OutDir "RV-remediate-$env:COMPUTERNAME-$stamp.txt"
$exitCode = 0
$psPolicyKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$sblKeys = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'

$agentDir = @('C:\Program Files (x86)\ossec-agent', 'C:\Program Files\ossec-agent') | Where-Object { Test-Path $_ } | Select-Object -First 1
$conf = if ($agentDir) { Join-Path $agentDir 'ossec.conf' }
$sharedConf = if ($agentDir) { Join-Path $agentDir 'shared\agent.conf' }

function Read-AgentXml {
  param([string]$Text)
  try { [xml]('<root>' + $Text + '</root>') } catch { $null }
}
function Get-AgentStatus {
  $sf = if ($agentDir) { Join-Path $agentDir 'wazuh-agent.state' }
  if ($sf -and (Test-Path $sf)) { $m = Select-String -LiteralPath $sf -Pattern "status='(\w+)'"; if ($m) { return $m.Matches[0].Groups[1].Value } }
  'unknown'
}
function Wait-Connected {
  param([int]$Sec = 90)
  $t = (Get-Date).AddSeconds($Sec)
  while ((Get-Date) -lt $t) {
    Start-Sleep 5
    if ((Get-AgentStatus) -eq 'connected' -and (Get-Service WazuhSvc).Status -eq 'Running') { return $true }
  }
  $false
}
function Restart-Agent {
  Restart-Service WazuhSvc -Force
  Wait-Connected 90
}

Start-Transcript -LiteralPath $txt | Out-Null
try {
  Write-Host ("=== RV REMEDIATE | host {0} | {1} local / {2} UTC ===" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Cyan
  Write-Host ("Switches: FixAgentConfig={0} DisableInvocationLogging={1} FirewallLogging={2} EnablePublicFirewall={3} WhatIf={4}" -f [bool]$FixAgentConfig, [bool]$DisableInvocationLogging, [bool]$FirewallLogging, [bool]$EnablePublicFirewall, [bool]$WhatIfPreference)

  # ---------- Restore mode ----------
  if ($Restore) {
    Step "Restore from $Restore"
    if (-not (Test-Path $Restore)) { throw "backup folder not found: $Restore" }
    $bConf = Join-Path $Restore 'ossec.conf'
    if ($conf -and (Test-Path $bConf) -and $PSCmdlet.ShouldProcess($conf, 'restore ossec.conf and restart agent')) {
      Copy-Item $bConf $conf -Force
      if (Restart-Agent) { Write-Host '  ossec.conf restored, agent connected' -ForegroundColor Green } else { Warn 'ossec.conf restored, agent NOT connected - check manually' }
    }
    $bReg = Join-Path $Restore 'ps-policy.reg'
    if (Test-Path $bReg) {
      if ($PSCmdlet.ShouldProcess($psPolicyKey, 'reg import')) { reg.exe import $bReg 2>&1 | Out-Null; Write-Host '  PowerShell policy restored' }
    } else { Warn 'ps-policy.reg not in backup (the policy key did not exist at backup time)' }
    $bFw = Join-Path $Restore 'fw-profiles-before.csv'
    if (Test-Path $bFw) {
      foreach ($p in (Import-Csv $bFw)) {
        if ($PSCmdlet.ShouldProcess("firewall profile $($p.Name)", 'restore')) {
          Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled -LogBlocked $p.LogBlocked -LogAllowed $p.LogAllowed -LogFileName $p.LogFileName
          Write-Host "  firewall profile $($p.Name) restored"
        }
      }
    }
    return
  }

  # ---------- 0. Backup ----------
  Step '[0] Backup'
  $bk = Join-Path $OutDir "backup-$stamp"; New-Item -ItemType Directory -Force $bk | Out-Null
  if ($conf -and (Test-Path $conf)) { Copy-Item $conf (Join-Path $bk 'ossec.conf') -Force }
  reg.exe export $psPolicyKey (Join-Path $bk 'ps-policy.reg') /y 2>&1 | Out-Null
  Get-NetFirewallProfile | Select-Object Name, Enabled, LogBlocked, LogAllowed, LogFileName | Export-Csv (Join-Path $bk 'fw-profiles-before.csv') -NoTypeInformation
  Write-Host "  ossec.conf, PowerShell policy, firewall profiles -> $bk"
  Write-Host "  roll back with: .\RV-Remediate.ps1 -Restore $bk"

  # ---------- 1. Agent config: duplicated channels + local buffer ----------
  Step '[1] Agent config: duplicated channels and local buffer'
  if (-not $FixAgentConfig) { Write-Host '  skipped (no -FixAgentConfig)' }
  elseif (-not ($conf -and (Test-Path $conf))) { Warn 'ossec.conf not found' }
  elseif (-not (Test-Path $sharedConf)) { Warn 'shared\agent.conf not found - group config not received, nothing removed' }
  else {
    $gx = Read-AgentXml (Get-Content -LiteralPath $sharedConf -Raw)
    if (-not $gx) { throw 'shared\agent.conf is not valid XML - nothing removed' }
    $groupLoc = @($gx.SelectNodes('//localfile/location') | ForEach-Object { $_.InnerText.Trim() } | Select-Object -Unique)
    $groupHasBuffer = [bool]$gx.SelectSingleNode('//client_buffer')
    Write-Host "  channels in group agent.conf: $($groupLoc.Count); group client_buffer: $groupHasBuffer"

    # regex keeps the file formatting and comments; the result is validated as XML before writing
    $raw = Get-Content -LiteralPath $conf -Raw; $orig = $raw; $removed = 0
    foreach ($l in $groupLoc) {
      $re = '(?s)[ \t]*<localfile>(?:(?!</localfile>).)*?<location>\s*' + [regex]::Escape($l) + '\s*</location>(?:(?!</localfile>).)*?</localfile>[ \t]*\r?\n?'
      $n = ([regex]::Matches($raw, $re)).Count
      if ($n) { $raw = [regex]::Replace($raw, $re, ''); $removed += $n; Write-Host "  local duplicate: $l" }
    }
    Write-Host "  local duplicates to remove: $removed (channels that are NOT in the group stay)"
    if ($groupHasBuffer) {
      $reB = '(?s)[ \t]*<client_buffer>.*?</client_buffer>[ \t]*\r?\n?'
      if ([regex]::IsMatch($raw, $reB)) { $raw = [regex]::Replace($raw, $reB, ''); Write-Host '  local <client_buffer> to remove - the group value will apply' }
    } else { Write-Host '  local <client_buffer> kept: the group does not define one' }

    if ($raw -eq $orig) { Write-Host '  nothing to change' }
    elseif (-not (Read-AgentXml $raw)) { Warn 'result is not valid XML - NOT applied' }
    elseif ($PSCmdlet.ShouldProcess($conf, "remove $removed duplicated <localfile> and restart agent")) {
      [IO.File]::WriteAllText($conf, $raw, (New-Object Text.UTF8Encoding($false)))
      if (Restart-Agent) { Write-Host '  agent restarted and connected' -ForegroundColor Green }
      else {
        Warn 'agent did not reconnect in 90 s - ROLLBACK'
        Copy-Item (Join-Path $bk 'ossec.conf') $conf -Force
        $exitCode = 3
        if (Restart-Agent) { Write-Host '  rollback OK, agent connected' } else { Warn 'agent still not connected after rollback - check manually' }
      }
    }
  }

  # ---------- 2. Script Block Invocation Logging (4105/4106) ----------
  Step '[2] Script Block Invocation Logging (4105/4106); 4104 stays ON'
  $existing = @($sblKeys | Where-Object { Test-Path $_ })
  if (-not $existing) { Warn 'ScriptBlockLogging policy keys not found - nothing to change (is 4104 enabled at all?)' }
  foreach ($k in $existing) {
    $p = Get-ItemProperty $k
    Write-Host ("  {0}: EnableScriptBlockLogging={1} EnableScriptBlockInvocationLogging={2}" -f $k, $p.EnableScriptBlockLogging, $p.EnableScriptBlockInvocationLogging)
    if ($DisableInvocationLogging -and $PSCmdlet.ShouldProcess($k, 'EnableScriptBlockInvocationLogging = 0')) {
      try { Set-ItemProperty -Path $k -Name EnableScriptBlockInvocationLogging -Value 0 -Type DWord -ErrorAction Stop; Write-Host '    -> EnableScriptBlockInvocationLogging = 0' -ForegroundColor Green }
      catch { Warn "failed: $($_.Exception.Message)" }
    }
  }
  if (-not $DisableInvocationLogging) { Write-Host '  no change (no -DisableInvocationLogging)' }

  # ---------- 3. Firewall ----------
  Step '[3] Firewall'
  if ($FirewallLogging) {
    foreach ($pr in 'Domain', 'Private', 'Public') {
      $file = "%systemroot%\system32\LogFiles\Firewall\$($pr.ToLower())fw.log"
      if ($PSCmdlet.ShouldProcess("firewall profile $pr", "LogBlocked=True, LogFileName=$file")) {
        try { Set-NetFirewallProfile -Profile $pr -LogBlocked True -LogFileName $file -LogMaxSizeKilobytes 32767 -ErrorAction Stop; Write-Host "  $pr : LogBlocked=True, $file" -ForegroundColor Green }
        catch { Warn "$pr failed: $($_.Exception.Message)" }
      }
    }
  } else { Write-Host '  logging: no change (no -FirewallLogging)' }
  if ($EnablePublicFirewall) {
    if ($PSCmdlet.ShouldProcess('firewall profile Public', 'Enabled=True')) {
      try { Set-NetFirewallProfile -Profile Public -Enabled True -ErrorAction Stop; Write-Host '  Public firewall ENABLED' -ForegroundColor Green }
      catch { Warn "failed: $($_.Exception.Message)" }
    }
  } else { Write-Host '  Public firewall: no change (no -EnablePublicFirewall)' }

  # ---------- 4. Validation ----------
  Step '[4] Validation via RV-Validation.ps1'
  if ($NoValidation -or $WhatIfPreference) { Write-Host '  skipped' }
  else {
    $val = @((Join-Path $PSScriptRoot 'RV-Validation.ps1'), (Join-Path $OutDir 'RV-Validation.ps1')) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $val) {
      $val = Join-Path $OutDir 'RV-Validation.ps1'
      Write-Host "  not found locally, downloading $ValidatorUrl"
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      Invoke-RestMethod $ValidatorUrl -OutFile $val -ErrorAction Stop
    }
    Write-Host "  running $val"
    # -Command (not -File) so that -Only is passed as an array
    $cmd = "& '$val' -OutDir '$OutDir' -AgentName '$AgentName'"
    if ($Only) { $cmd += " -Only $($Only -join ',')" }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$cmd; exit `$LASTEXITCODE"
    $valCode = $LASTEXITCODE
    if (-not $exitCode) { $exitCode = $valCode }
  }

  Write-Host ("`n=== Done. Send: {0} and the RV-validation-*.txt/.csv from {1} ===" -f $txt, $OutDir) -ForegroundColor Green
} catch {
  Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
  if (-not $exitCode) { $exitCode = 1 }
} finally {
  Stop-Transcript | Out-Null
}
Exit-Script $exitCode

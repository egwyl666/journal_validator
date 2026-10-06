<#
.SYNOPSIS
  RV-Validation.ps1 - control validation after closing audit gaps (ASCII only, no encoding issues).

.DESCRIPTION
  Does not change the system permanently (persistent fixes live in RV-Remediate.ps1).
  0. Preflight: audit policy (auditpol, by GUID - works on any OS language),
     CommandLine-in-4688 and PowerShell Script Block Logging registry settings.
  1. Creates test events. Every created object (service, task, firewall rule, local user)
     is removed in a finally block, even if a step fails or the run is interrupted.
  2. Polls local event logs until all events are found or -TimeoutSec expires.
  3. Wazuh agent diagnostics: service, state, ossec.log (buffer/flood/connection),
     duplicated channel subscriptions (ossec.conf vs shared agent.conf), network/firewall profiles.
     Optionally checks that the events reached Wazuh (-IndexerUrl).
  4. -Stats: firewall rule change history and top Event IDs per log for the last 24h.
  Results: <OutDir>\RV-validation-<host>-<time>.txt / .csv
  Exit code: 0 - everything found, 1 - something MISSING, 2 - not run as Administrator.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\RV-Validation.ps1
.EXAMPLE
  .\RV-Validation.ps1 -Skip share,user -TimeoutSec 60 -Stats
.EXAMPLE
  .\RV-Validation.ps1 -Only task,firewall
.EXAMPLE
  .\RV-Validation.ps1 -IndexerUrl https://wazuh-indexer:9200 -IndexerCredential (Get-Credential) -SkipCertificateCheck
#>
[CmdletBinding()]
param(
  # Folder for the .txt transcript and .csv results
  [string]$OutDir = 'C:\SOC_Audit',
  # How long to wait for events in local logs
  [ValidateRange(5, 600)][int]$TimeoutSec = 30,
  # Test groups to skip
  [ValidateSet('cmd', 'logon', 'service', 'task', 'firewall', 'share', 'user', 'powershell')][string[]]$Skip = @(),
  # Run only these test groups (cannot be combined with -Skip)
  [ValidateSet('cmd', 'logon', 'service', 'task', 'firewall', 'share', 'user', 'powershell')][string[]]$Only = @(),
  # 24h statistics: firewall rule change history, top Event IDs per log (can take a few minutes)
  [Alias('PsStats')][switch]$Stats,
  # Wazuh indexer (OpenSearch) URL, e.g. https://10.0.0.5:9200. Empty - Wazuh delivery is not checked
  [string]$IndexerUrl,
  [pscredential]$IndexerCredential,
  # agent.name in Wazuh, if it differs from the host name
  [string]$AgentName = $env:COMPUTERNAME,
  # How long to wait for alerts in the indexer
  [ValidateRange(0, 1800)][int]$WazuhWaitSec = 120,
  # Accept self-signed indexer certificate
  [switch]$SkipCertificateCheck
)
$ErrorActionPreference = 'Continue'

function Step { param($t) Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $t) -ForegroundColor Cyan }
function Warn { param($t) Write-Host "    $t" -ForegroundColor Yellow }

# exit would close the whole console when the script runs as a scriptblock (irm | scriptblock one-liner)
function Exit-Script {
  param([int]$Code)
  if ($MyInvocation.PSCommandPath) { exit $Code }
  $global:LASTEXITCODE = $Code
}

if ($Only -and $Skip) {
  Write-Host '-Only and -Skip cannot be used together.' -ForegroundColor Red
  Exit-Script 2
  return
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'Run this script as Administrator (Security log, sc, schtasks, firewall and local users need it).' -ForegroundColor Red
  Exit-Script 2
  return
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$txt = Join-Path $OutDir "RV-validation-$env:COMPUTERNAME-$stamp.txt"
$csv = Join-Path $OutDir "RV-validation-$env:COMPUTERNAME-$stamp.csv"
$marker = "RVTEST$stamp"
$fakeUser = 'rv_fake_user'
$rvUser = 'rv_' + (Get-Random -Minimum 100000 -Maximum 999999)  # local user names are limited to 20 chars
$exitCode = 0
$groups = @('cmd', 'logon', 'service', 'task', 'firewall', 'share', 'user', 'powershell')
if ($Only) { $Skip = @($groups | Where-Object { $Only -notcontains $_ }) }
$psLog = 'Microsoft-Windows-PowerShell/Operational'

# --- Helpers ---
function Get-EvData {
  param([string]$Xml)
  $h = @{}
  foreach ($d in ([xml]$Xml).Event.EventData.Data) { if ($d.Name) { $h[$d.Name] = $d.'#text' } }
  $h
}

function Test-Substring {
  param([string]$Text, [string]$Value)
  $Text -and $Text.IndexOf($Value, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

# auditpol by GUID: subcategory names are localized, GUIDs are not
function Get-AuditSetting {
  param([string]$Guid)
  $o = auditpol.exe /get /subcategory:"{$Guid}" /r 2>$null
  if ($LASTEXITCODE -or -not $o) { return 'n/a' }
  $r = $o | Where-Object { $_ } | ConvertFrom-Csv | Select-Object -First 1
  if (-not $r) { return 'n/a' }
  @($r.PSObject.Properties)[4].Value  # 'Inclusion Setting' (header is localized too)
}

function Get-SblState {
  $s = foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging') {
    $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if ($p) { '{0}: Logging={1} Invocation={2}' -f ($k -replace '^.*\\Microsoft\\', ''), $p.EnableScriptBlockLogging, $p.EnableScriptBlockInvocationLogging }
  }
  if ($s) { $s -join '; ' } else { 'ScriptBlockLogging policy: not set' }
}

# Wazuh config files may contain several <ossec_config> roots - wrap them; XML parsing ignores commented-out blocks
function Read-AgentXml {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try { [xml]('<root>' + (Get-Content -LiteralPath $Path -Raw) + '</root>') }
  catch { Warn "$(Split-Path $Path -Leaf) is not valid XML: $($_.Exception.Message)"; $null }
}

# Event ID counts without rendering events (fast, max $Max events)
function Get-IdCount {
  param([string]$Log, [int]$Hours = 24, [int]$Max = 300000)
  $from = (Get-Date).AddHours(-$Hours).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Log, [System.Diagnostics.Eventing.Reader.PathType]::LogName, "*[System[TimeCreated[@SystemTime>='$from']]]")
  $r = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
  $by = @{}; $n = 0
  try {
    while ($null -ne ($e = $r.ReadEvent())) { $k = $e.Id; if ($by.ContainsKey($k)) { $by[$k]++ } else { $by[$k] = 1 }; $e.Dispose(); $n++; if ($n -ge $Max) { break } }
  } finally { $r.Dispose() }
  [pscustomobject]@{ Total = $n; ById = $by; Capped = ($n -ge $Max) }
}

# Newest events as XML strings via wevtutil (not recorded by PowerShell Module Logging)
function Read-EvXml {
  param([string]$Log, [string]$Query, [int]$Max = 200)
  $raw = (wevtutil.exe qe "$Log" "/q:$Query" /c:$Max /rd:true /e:Events 2>$null) -join ''
  if (-not $raw) { return @() }
  @([regex]::Matches($raw, '<Event .*?</Event>') | ForEach-Object { $_.Value })
}

function Invoke-Indexer {
  param([hashtable]$Body)
  $p = @{
    Uri         = "$($IndexerUrl.TrimEnd('/'))/wazuh-alerts-*/_search"
    Method      = 'Post'
    ContentType = 'application/json'
    Body        = ($Body | ConvertTo-Json -Depth 10)
    ErrorAction = 'Stop'
  }
  if ($IndexerCredential) {
    $pair = '{0}:{1}' -f $IndexerCredential.UserName, $IndexerCredential.GetNetworkCredential().Password
    $p.Headers = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair)) }
  }
  if ($PSVersionTable.PSVersion.Major -ge 6) {
    if ($SkipCertificateCheck) { $p.SkipCertificateCheck = $true }
  } else {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ($SkipCertificateCheck) { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
  }
  Invoke-RestMethod @p
}

# --- Test definitions ---
# Gen      - generator group (see $actions, -Skip)
# Sub      - audit subcategory GUID that produces the event ('' - always logged)
# Filter   - { param($d, $x) } $d = EventData hashtable, $x = event XML; default: XML contains marker
# WMatch   - string that must be in the Wazuh alert JSON
$byMarker = { param($d, $x) Test-Substring $x $marker }
$tests = @(
  @{ Gen = 'cmd';      Test = 'cmd /c echo marker';        Id = 4688; Log = 'Security'; Sub = '0CCE922B-69AE-11D9-BED3-505054503030'; Before = 'No auditing';            After = 'Success + CommandLine'
     Filter = { param($d, $x) $d.NewProcessName -like '*\cmd.exe' }; WMatch = $marker }
  @{ Gen = 'logon';    Test = "failed logon $fakeUser";    Id = 4625; Log = 'Security'; Sub = '0CCE9215-69AE-11D9-BED3-505054503030'; Before = 'Visible';                After = 'Visible'
     Filter = { param($d, $x) $d.TargetUserName -eq $fakeUser }; WMatch = $fakeUser }
  @{ Gen = 'logon';    Test = "failed logon $fakeUser";    Id = 4776; Log = 'Security'; Sub = '0CCE923F-69AE-11D9-BED3-505054503030'; Before = 'Success only';           After = 'Success and Failure'
     Filter = { param($d, $x) $d.TargetUserName -eq $fakeUser }; WMatch = $fakeUser }
  @{ Gen = 'service';  Test = 'sc create / delete';        Id = 4697; Log = 'Security'; Sub = '0CCE9211-69AE-11D9-BED3-505054503030'; Before = 'No auditing';            After = 'Success' }
  @{ Gen = 'service';  Test = 'sc create / delete';        Id = 7045; Log = 'System';   Sub = '';                                     Before = 'Always logged';          After = 'Always logged' }
  @{ Gen = 'task';     Test = 'schtasks /create';          Id = 4698; Log = 'Security'; Sub = '0CCE9227-69AE-11D9-BED3-505054503030'; Before = 'TaskScheduler 106 only'; After = '4698 with task XML' }
  @{ Gen = 'task';     Test = 'schtasks /delete';          Id = 4699; Log = 'Security'; Sub = '0CCE9227-69AE-11D9-BED3-505054503030'; Before = 'TaskScheduler 141 only'; After = '4699' }
  @{ Gen = 'firewall'; Test = 'New-NetFirewallRule';       Id = 4946; Log = 'Security'; Sub = '0CCE9232-69AE-11D9-BED3-505054503030'; Before = 'Firewall 2004 only';     After = '4946' }
  @{ Gen = 'firewall'; Test = 'Set-NetFirewallRule';       Id = 4947; Log = 'Security'; Sub = '0CCE9232-69AE-11D9-BED3-505054503030'; Before = 'Firewall 2005 only';     After = '4947' }
  @{ Gen = 'firewall'; Test = 'Remove-NetFirewallRule';    Id = 4948; Log = 'Security'; Sub = '0CCE9232-69AE-11D9-BED3-505054503030'; Before = 'Firewall 2006 only';     After = '4948' }
  @{ Gen = 'share';    Test = 'dir \\127.0.0.1\C$';        Id = 5140; Log = 'Security'; Sub = '0CCE9224-69AE-11D9-BED3-505054503030'; Before = 'No auditing';            After = 'Success'
     Filter = { param($d, $x) $d.ShareName -like '*\C$' -and @('127.0.0.1', '::1', '::ffff:127.0.0.1') -contains $d.IpAddress }; WMatch = 'C$' }
  @{ Gen = 'user';     Test = 'local user create';         Id = 4720; Log = 'Security'; Sub = '0CCE9235-69AE-11D9-BED3-505054503030'; Before = '?';                      After = 'Success'
     Filter = { param($d, $x) $d.TargetUserName -eq $rvUser }; WMatch = $rvUser }
  @{ Gen = 'user';     Test = 'local user delete';         Id = 4726; Log = 'Security'; Sub = '0CCE9235-69AE-11D9-BED3-505054503030'; Before = '?';                      After = 'Success'
     Filter = { param($d, $x) $d.TargetUserName -eq $rvUser }; WMatch = $rvUser }
  @{ Gen = 'powershell'; Test = 'powershell script block';  Id = 4104; Log = $psLog;     Sub = '';                                     Before = '?';                      After = '4104 on, 4105/4106 off' }
)
for ($i = 0; $i -lt $tests.Count; $i++) { $tests[$i].Idx = $i }
foreach ($t in $tests) {
  if (-not $t.Filter) { $t.Filter = $byMarker }
  if (-not $t.WMatch) { $t.WMatch = $marker }
}

# --- Generators: Do creates, Undo always runs in finally ---
$actions = [ordered]@{
  cmd      = @{ Do = { cmd.exe /c "echo $marker" | Out-Null; if ($LASTEXITCODE) { throw "cmd.exe exit code $LASTEXITCODE" } } }
  logon    = @{ Do = {
      Add-Type -AssemblyName System.DirectoryServices.AccountManagement
      $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
      try { [void]$ctx.ValidateCredentials($fakeUser, 'WrongPass_123') } finally { $ctx.Dispose() }
    } }
  service  = @{
    Do   = { $o = sc.exe create "$marker-svc" binPath= "C:\Windows\System32\cmd.exe /c exit" 2>&1; if ($LASTEXITCODE) { throw "sc create: $o" } }
    Undo = { $o = sc.exe delete "$marker-svc" 2>&1; if ($LASTEXITCODE) { throw "sc delete: $o" } }
  }
  task     = @{
    Do   = { $o = schtasks.exe /create /tn "$marker-task" /tr notepad.exe /sc once /st 23:59 /f 2>&1; if ($LASTEXITCODE) { throw "schtasks /create: $o" } }
    Undo = { $o = schtasks.exe /delete /tn "$marker-task" /f 2>&1; if ($LASTEXITCODE) { throw "schtasks /delete: $o" } }
  }
  firewall = @{
    Do   = {
      New-NetFirewallRule -DisplayName "$marker-fw" -Direction Inbound -Action Block -Protocol TCP -LocalPort 65000 -ErrorAction Stop | Out-Null
      Set-NetFirewallRule -DisplayName "$marker-fw" -Description 'rv change test' -ErrorAction Stop  # 4947
    }
    Undo = { Remove-NetFirewallRule -DisplayName "$marker-fw" -ErrorAction Stop }
  }
  share    = @{ Do = { Get-ChildItem '\\127.0.0.1\C$' -ErrorAction Stop | Select-Object -First 1 | Out-Null } }
  user     = @{
    # ADSI instead of 'net user': the password does not end up in 4688 CommandLine
    Do   = {
      $pw = 'Rv!' + [guid]::NewGuid().ToString('N') + 'aA1'
      $u = ([ADSI]"WinNT://$env:COMPUTERNAME").Create('User', $rvUser)
      $u.SetPassword($pw); $u.SetInfo()
    }
    Undo = { ([ADSI]"WinNT://$env:COMPUTERNAME").Delete('User', $rvUser) }
  }
  # child process so its script block is logged as a separate 4104 with the marker
  powershell = @{ Do = { $o = powershell.exe -NoProfile -Command "Write-Output 'PSCHECK_$marker'" 2>&1; if ($LASTEXITCODE) { throw "powershell.exe: $o" } } }
}

Start-Transcript -LiteralPath $txt | Out-Null
try {
  $start = (Get-Date).AddSeconds(-2)
  Write-Host ("=== RV validation | host {0} | start {1} (UTC {2}) | marker {3} ===" -f $env:COMPUTERNAME, $start.ToString('yyyy-MM-dd HH:mm:ss'), $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $marker) -ForegroundColor Cyan
  if ($Skip) { Write-Host "Skipped groups: $($Skip -join ', ')" }

  # --- 0. Preflight ---
  Step '[0] Preflight: audit policy'
  $audit = @{}
  foreach ($g in ($tests | Where-Object { $_.Sub } | ForEach-Object { $_.Sub } | Select-Object -Unique)) { $audit[$g] = Get-AuditSetting $g }
  $tests | Where-Object { $_.Sub } | ForEach-Object { [pscustomobject]@{ EventID = $_.Id; Expected = $_.After; AuditPolicy = $audit[$_.Sub] } } |
    Format-Table -AutoSize | Out-String -Width 200 | Write-Host
  $cmdLineKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
  if ($cmdLineKey -and $cmdLineKey.ProcessCreationIncludeCmdLine_Enabled -eq 1) { Write-Host 'ProcessCreationIncludeCmdLine_Enabled: 1 (CommandLine in 4688)' }
  else { Write-Host 'ProcessCreationIncludeCmdLine_Enabled: NOT set (4688 without CommandLine)' -ForegroundColor Yellow }
  $sbl = Get-SblState
  Write-Host $sbl

  # --- 1. Generate events ---
  Step '[1] Generating test events'
  $genErr = @{}
  foreach ($k in $actions.Keys) {
    if ($Skip -contains $k) { continue }
    $a = $actions[$k]
    Step "  $k"
    $ok = $false
    try { & $a.Do; $ok = $true }
    catch { $genErr[$k] = "generate failed: $($_.Exception.Message)"; Warn $genErr[$k] }
    finally {
      if ($a.Undo) {
        try { & $a.Undo }
        catch {
          # if Do failed there may be nothing to remove
          if ($ok) { $genErr[$k] = "CLEANUP FAILED, remove manually: $($_.Exception.Message)"; Write-Host "    $($genErr[$k])" -ForegroundColor Red }
        }
      }
    }
  }

  # --- 2. Check local event logs (poll until found or timeout) ---
  Step "[2] Checking local event logs (up to $TimeoutSec s)"
  $active = @($tests | Where-Object { $Skip -notcontains $_.Gen })
  $found = @{}
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  do {
    foreach ($t in $active) {
      if ($found.ContainsKey($t.Idx)) { continue }
      $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $t.Log; Id = $t.Id; StartTime = $start } -ErrorAction SilentlyContinue)
      $t.Seen = $ev.Count
      $hit = @(foreach ($e in $ev) {
          $x = $e.ToXml()
          if (& $t.Filter (Get-EvData $x) $x) { [pscustomobject]@{ Event = $e; Xml = $x } }
        })
      if ($hit.Count) { $found[$t.Idx] = $hit }
    }
    if ($found.Count -ge $active.Count -or (Get-Date) -ge $deadline) { break }
    Start-Sleep -Seconds 2
  } while ($true)

  $rows = foreach ($t in $tests) {
    $row = [ordered]@{
      Test = $t.Test; EventID = $t.Id; Log = $t.Log; Local = 'SKIPPED'; LocalFound = 0; LocalTime = ''; RecordId = ''
      AuditPolicy = $(if ($t.Sub) { $audit[$t.Sub] } else { 'n/a' }); Before = $t.Before; After = $t.After; Note = ''; Wazuh = ''
    }
    if ($Skip -notcontains $t.Gen) {
      $hit = $found[$t.Idx]
      if ($hit) {
        $first = $hit | Sort-Object { $_.Event.TimeCreated } | Select-Object -First 1
        if ($t.Id -eq 4688) {
          $withCmd = $hit | Where-Object { Test-Substring (Get-EvData $_.Xml).CommandLine $marker } | Select-Object -First 1
          if ($withCmd) { $first = $withCmd; $row.Note = 'CommandLine: logged' } else { $row.Note = 'CommandLine: NOT logged' }
        }
        $row.Local = 'OK'; $row.LocalFound = @($hit).Count
        $row.LocalTime = $first.Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); $row.RecordId = $first.Event.RecordId
      } else {
        $row.Local = 'MISSING'
        if ($t.Seen) { $row.Note = "events with this ID exist ($($t.Seen)), but none match" }
      }
      if ($t.Id -eq 4104) {
        $inv = @(Get-WinEvent -FilterHashtable @{ LogName = $psLog; Id = 4105, 4106; StartTime = $start } -ErrorAction SilentlyContinue).Count
        $row.AuditPolicy = $sbl
        $row.Note = (@($row.Note, "4105/4106 since start: $inv (expected 0)") | Where-Object { $_ }) -join '; '
      }
      if ($genErr[$t.Gen]) { $row.Note = (@($row.Note, $genErr[$t.Gen]) | Where-Object { $_ }) -join '; ' }
    }
    [pscustomobject]$row
  }

  # --- 3. Wazuh agent and firewall diagnostics (read-only) ---
  Step '[3] Wazuh agent'
  $svc = Get-Service WazuhSvc -ErrorAction SilentlyContinue
  if ($svc) { Write-Host "WazuhSvc service: $($svc.Status)" } else { Write-Host 'WazuhSvc service: not found' -ForegroundColor Yellow }
  $agentDir = @('C:\Program Files (x86)\ossec-agent', 'C:\Program Files\ossec-agent') | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($agentDir) {
    $state = Join-Path $agentDir 'wazuh-agent.state'
    if (Test-Path $state) {
      Write-Host 'wazuh-agent.state:'
      Get-Content $state | Where-Object { $_ -match '^\w+=' } | ForEach-Object { Write-Host "  $_" }
    }
    $proc = Get-Process -Name 'wazuh-agent' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) { Write-Host "Agent process start: $($proc.StartTime)" }

    $log = Join-Path $agentDir 'ossec.log'
    if (Test-Path $log) {
      $lines = @(Get-Content -LiteralPath $log -Tail 20000)
      Write-Host 'ossec.log - last ERROR/WARNING lines:'
      $lines | Where-Object { $_ -match 'ERROR|WARNING' } | Select-Object -Last 15 | ForEach-Object { Write-Host "  $_" }
      $buf = @($lines | Where-Object { $_ -match 'buffer|flood|drop|discard' })
      if ($buf.Count) { Write-Host "ossec.log - buffer/flood/drop lines: $($buf.Count) (last 15):" -ForegroundColor Yellow; $buf | Select-Object -Last 15 | ForEach-Object { Write-Host "  $_" } }
      else { Write-Host 'ossec.log - no buffer/flood/drop messages in last 20000 lines' }
      Write-Host 'ossec.log - connection events (last 10):'
      $lines | Where-Object { $_ -match 'Lost connection|Connected to the server' } | Select-Object -Last 10 | ForEach-Object { Write-Host "  $_" }
    }

    # Channel subscriptions: local ossec.conf vs group shared\agent.conf
    $subs = @()
    foreach ($f in 'ossec.conf', 'shared\agent.conf') {
      $cx = Read-AgentXml (Join-Path $agentDir $f)
      if (-not $cx) { continue }
      foreach ($n in $cx.SelectNodes('//localfile[location]')) {
        $subs += [pscustomobject]@{ Location = $n.location.Trim(); Format = "$($n.log_format)".Trim(); File = $f }
      }
      foreach ($n in $cx.SelectNodes('//client_buffer/queue_size | //client_buffer/events_per_second')) { Write-Host ("{0}: {1} = {2}" -f $f, $n.Name, $n.InnerText.Trim()) }
    }
    $secIn = @($subs | Where-Object { $_.Location -eq 'Security' -and $_.Format -eq 'eventchannel' } | ForEach-Object { $_.File } | Select-Object -Unique)
    if ($secIn) { Write-Host "Security channel subscribed in: $($secIn -join ', ')" } else { Write-Host 'Security channel subscribed: NO' -ForegroundColor Yellow }
    $dups = @($subs | Group-Object Location | Where-Object { $_.Count -gt 1 })
    if ($dups) {
      Write-Host 'Channels defined more than once (events are collected twice):' -ForegroundColor Yellow
      foreach ($g in $dups) { Write-Host ("  {0} <- {1}" -f $g.Name, (($g.Group | ForEach-Object { $_.File }) -join ', ')) }
    } else { Write-Host "No duplicated channels ($(@($subs | Select-Object -ExpandProperty Location -Unique).Count) unique locations)" }
  } else { Write-Host 'Wazuh agent folder not found' -ForegroundColor Yellow }

  Step '[3a] Network and firewall profiles'
  try {
    foreach ($c in (Get-NetConnectionProfile -ErrorAction Stop)) { Write-Host ("  Connection: {0} | {1} | {2}" -f $c.Name, $c.InterfaceAlias, $c.NetworkCategory) }
    foreach ($f in (Get-NetFirewallProfile -ErrorAction Stop)) { Write-Host ("  FW profile: {0} | Enabled={1} | LogBlocked={2} | LogAllowed={3} | {4}" -f $f.Name, $f.Enabled, $f.LogBlocked, $f.LogAllowed, $f.LogFileName) }
  } catch { Warn "profiles: $($_.Exception.Message)" }

  # --- 3b. Delivery to Wazuh indexer (optional) ---
  if ($IndexerUrl) {
    Step "[3b] Wazuh indexer: alerts for agent '$AgentName' (up to $WazuhWaitSec s)"
    $wTests = @($rows | Where-Object { $_.Local -ne 'SKIPPED' })
    $ids = @($wTests | ForEach-Object { [string]$_.EventID } | Select-Object -Unique)
    $body = @{
      size    = 1000
      _source = @('timestamp', 'rule.id', 'rule.description', 'data.win.system.eventID', 'data.win.eventdata')
      query   = @{ bool = @{ filter = @(
            @{ term = @{ 'agent.name' = $AgentName } }
            @{ range = @{ timestamp = @{ gte = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } } }
            @{ terms = @{ 'data.win.system.eventID' = $ids } }
          ) } }
    }
    $wDeadline = (Get-Date).AddSeconds($WazuhWaitSec)
    $wErr = $null
    do {
      try { $resp = Invoke-Indexer $body; $wErr = $null } catch { $wErr = $_.Exception.Message; $resp = $null }
      $alerts = @(if ($resp) { $resp.hits.hits | ForEach-Object { $_._source } })
      foreach ($r in $wTests) {
        $t = $tests | Where-Object { $_.Id -eq $r.EventID } | Select-Object -First 1
        $m = @($alerts | Where-Object { [string]$_.data.win.system.eventID -eq [string]$r.EventID -and (Test-Substring ($_ | ConvertTo-Json -Depth 10 -Compress) $t.WMatch) })
        $r.Wazuh = $(if ($m.Count) { "OK (rule $($m[0].rule.id))" } else { 'MISSING' })
      }
      if (-not @($wTests | Where-Object { $_.Wazuh -eq 'MISSING' }).Count -or (Get-Date) -ge $wDeadline) { break }
      Start-Sleep -Seconds 10
    } while ($true)
    if ($wErr) { Warn "indexer request failed: $wErr"; $wTests | ForEach-Object { $_.Wazuh = 'ERROR' } }
  }

  # --- Results ---
  Step 'Results'
  $rows | Format-Table Test, EventID, Local, LocalFound, LocalTime, AuditPolicy, Wazuh, Note -AutoSize | Out-String -Width 300 | Write-Host
  $rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
  $checked = @($rows | Where-Object { $_.Local -ne 'SKIPPED' })
  $okLocal = @($checked | Where-Object { $_.Local -eq 'OK' }).Count
  $summary = "Local: $okLocal/$($checked.Count) OK"
  if ($IndexerUrl) { $summary += " | Wazuh: $(@($checked | Where-Object { $_.Wazuh -like 'OK*' }).Count)/$($checked.Count) OK" }
  $bad = $okLocal -lt $checked.Count -or ($IndexerUrl -and @($checked | Where-Object { $_.Wazuh -notlike 'OK*' }).Count)
  if ($bad) { $exitCode = 1; Write-Host $summary -ForegroundColor Red } else { Write-Host $summary -ForegroundColor Green }

  # --- 4. 24h statistics (optional: -Stats, can take a few minutes) ---
  if ($Stats) {
    Step '[4] Firewall rule changes, last 24h (newest 200 per source)'
    $w24 = 'TimeCreated[timediff(@SystemTime) <= 86400000]'
    $fieldOf = { param($x, $n) $m = [regex]::Match($x, "<Data Name='$n'>(.*?)</Data>"); if ($m.Success) { $m.Groups[1].Value } else { '' } }
    $headOf = { param($x) '{0} UTC  {1}' -f [regex]::Match($x, "SystemTime='([^']+)'").Groups[1].Value, [regex]::Match($x, '<EventID[^>]*>(\d+)</EventID>').Groups[1].Value }
    $fw = Read-EvXml 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' "*[System[(EventID=2004 or EventID=2005 or EventID=2006 or EventID=2033 or EventID=2097) and $w24]]"
    Write-Host "  Firewall channel 2004/2005/2006/2033/2097: $($fw.Count)"
    foreach ($x in $fw) { Write-Host ("    {0}  Rule='{1}'  App='{2}'  ModifyingUser='{3}'  ModifyingApp='{4}'" -f (& $headOf $x), (& $fieldOf $x 'RuleName'), (& $fieldOf $x 'ApplicationPath'), (& $fieldOf $x 'ModifyingUser'), (& $fieldOf $x 'ModifyingApplication')) }
    $fs = Read-EvXml 'Security' "*[System[(EventID=4946 or EventID=4947 or EventID=4948) and $w24]]"
    Write-Host "  Security 4946/4947/4948: $($fs.Count)"
    foreach ($x in $fs) { Write-Host ("    {0}  RecordId={1}  Rule='{2}'" -f (& $headOf $x), [regex]::Match($x, '<EventRecordID>(\d+)</EventRecordID>').Groups[1].Value, (& $fieldOf $x 'RuleName')) }
    $sy = @(Read-EvXml 'Microsoft-Windows-Sysmon/Operational' "*[System[EventID=1 and $w24]]" 2000 | Where-Object { $_ -match 'netsh|NetFirewallRule|MpCmdRun|TiWorker|MsMpEng' } | Select-Object -First 15)
    Write-Host "  Sysmon 1 matching netsh / NetFirewallRule / MpCmdRun / TiWorker / MsMpEng: $($sy.Count)"
    foreach ($x in $sy) { Write-Host ("    {0}  User='{1}'  Image='{2}'  Cmd='{3}'" -f (& $headOf $x), (& $fieldOf $x 'User'), (& $fieldOf $x 'Image'), (& $fieldOf $x 'CommandLine')) }

    foreach ($ln in 'Microsoft-Windows-Sysmon/Operational', $psLog, 'Windows PowerShell', 'Security') {
      Step "[4] Top Event IDs, last 24h: $ln"
      try {
        $c = Get-IdCount $ln
        Write-Host ("  total: {0}{1}" -f $c.Total, $(if ($c.Capped) { ' (capped)' } else { '' }))
        $c.ById.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { Write-Host ("    {0,-7} {1}" -f $_.Key, $_.Value) }
      } catch { Warn "$ln : $($_.Exception.Message)" }
    }
  } else { Step '[4] 24h statistics skipped (run with -Stats to include)' }

  Write-Host "`n=== Done. Please send these files: ===" -ForegroundColor Green
  Write-Host "  $txt"
  Write-Host "  $csv"
  Write-Host ("Wazuh search: agent.name:""{0}"" from {1} UTC, marker {2}, test user {3}" -f $AgentName, $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $marker, $rvUser)
  $rids = @($rows | Where-Object { $_.RecordId } | ForEach-Object { $_.RecordId })
  if ($rids) { Write-Host ("Dashboard: agent.name:""{0}"" and data.win.system.eventRecordID:({1})" -f $AgentName, ($rids -join ' or ')) }
  Write-Host 'On the Wazuh manager (archives.json needs <logall_json>yes</logall_json>):'
  Write-Host "  grep '$marker' /var/ossec/logs/archives/archives.json | grep -o '`"eventID`":`"[0-9]*`"' | sort | uniq -c"
  Write-Host "  grep '$marker' /var/ossec/logs/alerts/alerts.json | grep -o '`"rule`":{[^}]*}' | sort | uniq -c"
} finally {
  Stop-Transcript | Out-Null
}
Exit-Script $exitCode

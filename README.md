# RV-Validation

**English** | [Українська](README.uk.md)

A script for control validation of a Windows host after closing audit gaps.
It generates test events, looks for them in local event logs, checks the Wazuh agent
and (optionally) delivery of the events to the Wazuh indexer. Every object it creates
(service, task, firewall rule, local user) is removed right away, even if a step fails
or the run is interrupted with Ctrl+C.

Results are saved to `C:\SOC_Audit\RV-validation-<host>-<time>.txt` (log) and `.csv` (table).

## Scripts

| Script | Purpose | Changes the system |
|---|---|---|
| `RV-Validation.ps1` | Test events + read-only diagnostics: audit policy, agent state, buffer/flood, duplicated channels, firewall profiles, 24h statistics (`-Stats`) | Only temporarily (test objects are removed right away) |
| `RV-Remediate.ps1` | Agreed persistent fixes with backup, `-WhatIf` and `-Restore`; runs `RV-Validation.ps1` at the end | **Yes**, only with explicit switches |

Recommended order:

1. Run `RV-Validation.ps1` and review the result.
2. If fixes are agreed, run `RV-Remediate.ps1 ... -WhatIf` to preview them, then without `-WhatIf`.
   It makes a backup, applies the fixes and runs the validation again by itself.
3. If something goes wrong: `RV-Remediate.ps1 -Restore <backup folder>`.

## Quick start (one line)

You need PowerShell **running as Administrator**.

Download and run without saving anything to disk:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1)))
```

With flags (append them to the end of the line):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1))) -TimeoutSec 60 -Skip share -Stats
```

From `cmd.exe` or Run (Win+R). Downloads the file to `%TEMP%` first, then runs it:

```cmd
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; irm https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1 -OutFile $env:TEMP\RV-Validation.ps1; & $env:TEMP\RV-Validation.ps1"
```

Regular run from a downloaded file:

```powershell
powershell -ExecutionPolicy Bypass -File .\RV-Validation.ps1
```

> If `irm` fails with a TLS error on Windows PowerShell 5.1, run
> `[Net.ServicePointManager]::SecurityProtocol='Tls12'` first.

## Parameters

| Flag | Default | Description |
|---|---|---|
| `-OutDir <path>` | `C:\SOC_Audit` | Folder for `.txt` and `.csv` |
| `-TimeoutSec <5-600>` | `30` | How long to wait for events in local logs |
| `-Skip <groups>` | — | Skip test groups: `cmd`, `logon`, `service`, `task`, `firewall`, `share`, `user`, `powershell` |
| `-Only <groups>` | — | Run only these test groups (cannot be combined with `-Skip`), e.g. `-Only task,firewall` |
| `-Stats` | off | Firewall rule change history and top Event IDs (Sysmon, PowerShell, Security) for the last 24h; can take a few minutes. Old name `-PsStats` still works |
| `-IndexerUrl <url>` | — | Wazuh indexer (OpenSearch) URL, e.g. `https://10.0.0.5:9200`. Without it, Wazuh delivery is not checked |
| `-IndexerCredential <cred>` | — | Indexer account: `-IndexerCredential (Get-Credential)` |
| `-AgentName <name>` | host name | `agent.name` in Wazuh, if it differs from the computer name |
| `-WazuhWaitSec <0-1800>` | `120` | How long to wait for alerts in the indexer |
| `-SkipCertificateCheck` | off | Accept a self-signed indexer certificate |

Example with an end-to-end Wazuh delivery check:

```powershell
.\RV-Validation.ps1 -IndexerUrl https://wazuh-indexer:9200 -IndexerCredential (Get-Credential) -SkipCertificateCheck
```

> Only events that triggered a rule end up in `wazuh-alerts-*`. `MISSING` in the `Wazuh`
> column with `OK` in `Local` means either the event was not delivered or there is no rule for it.

## What is checked

| Group | Action | Event ID | Audit subcategory |
|---|---|---|---|
| `cmd` | `cmd /c echo <marker>` | 4688 (+ CommandLine check) | Process Creation |
| `logon` | wrong password for `rv_fake_user` | 4625, 4776 | Logon, Credential Validation |
| `service` | `sc create` / `sc delete` | 4697, 7045 | Security System Extension |
| `task` | `schtasks /create` / `/delete` | 4698, 4699 | Other Object Access Events |
| `firewall` | `New-` / `Set-` / `Remove-NetFirewallRule` | 4946, 4947, 4948 | MPSSVC Rule-Level Policy Change |
| `share` | `dir \\127.0.0.1\C$` | 5140 | File Share |
| `user` | create / delete local user `rv_NNNNNN` | 4720, 4726 | User Account Management |
| `powershell` | child `powershell.exe` with a marker | 4104 (+ count of 4105/4106, expected 0) | Script Block Logging policy |

After the tests the script checks the Wazuh agent: service, `wazuh-agent.state`, buffer/flood/drop and
connection lines in `ossec.log`, `queue_size` / `events_per_second`, channels defined more than once in
`ossec.conf` and the group `shared\agent.conf`, and the network / firewall profiles. At the end it prints a
dashboard query by `eventRecordID` and `grep` commands for the Wazuh manager.

Before the tests the script shows the current audit policy (`auditpol` by GUID, so it works
on any OS language) and the `ProcessCreationIncludeCmdLine_Enabled` registry value. They show
right away why an event is missing.

## RV-Remediate.ps1

Without switches it changes nothing: it makes a backup and runs the validation.

| Flag | Description |
|---|---|
| `-FixAgentConfig` | Remove from the local `ossec.conf` every `<localfile>` that also exists in the group `shared\agent.conf`, and the local `<client_buffer>` if the group defines one. Rolls back automatically if the agent does not reconnect within 90 s |
| `-DisableInvocationLogging` | `EnableScriptBlockInvocationLogging = 0` (stops 4105/4106, 4104 stays on) |
| `-FirewallLogging` | `LogBlocked = True` and log files `domainfw/privatefw/publicfw.log` (logging only, no traffic impact) |
| `-EnablePublicFirewall` | Turn on the firewall in the Public profile (**only with the server owner's approval**) |
| `-WhatIf` | Show what would be changed, change nothing |
| `-Restore <folder>` | Roll back from a `backup-<time>` folder |
| `-Only`, `-AgentName`, `-OutDir` | Passed to `RV-Validation.ps1` |
| `-NoValidation` | Do not run `RV-Validation.ps1` at the end |

```powershell
.\RV-Remediate.ps1 -FixAgentConfig -DisableInvocationLogging -FirewallLogging -WhatIf
.\RV-Remediate.ps1 -FixAgentConfig -DisableInvocationLogging -FirewallLogging
.\RV-Remediate.ps1 -Restore C:\SOC_Audit\backup-20261006_120000
```

`RV-Validation.ps1` is taken from the same folder, from `-OutDir`, or downloaded from GitHub.
Exit code: the validator's code, `2` — not Administrator, `3` — the agent config change was rolled back.

## Output

- CSV columns: `Test, EventID, Log, Local, LocalFound, LocalTime, RecordId, AuditPolicy, Before, After, Note, Wazuh`.
- `Local`: `OK` / `MISSING` / `SKIPPED`. `Wazuh`: `OK (rule N)` / `MISSING` / `ERROR`; empty when no indexer is set.
- Exit codes: `0` — everything found, `1` — something `MISSING`, `2` — not run as Administrator.
  When run with the scriptblock one-liner, the code goes to `$LASTEXITCODE` and the console stays open.

## Adding your own flag or test

1. **Flag.** Add a parameter to the `param(...)` block at the top of the script:
   ```powershell
   [switch]$NoCleanup,                          # switch
   [ValidateRange(1, 10)][int]$Repeat = 1,      # number with range check
   [ValidateSet('a', 'b')][string[]]$Only = @() # list of allowed values
   ```
   Then use `$NoCleanup` / `$Repeat` in the code and add a row to the parameters table above.
2. **New test.**
   - Add a generator to `$actions`: `Do` creates the event, `Undo` (if needed) removes what was created.
     `Undo` always runs in `finally`.
   - Add the expected event to `$tests` with the same `Gen`, plus `Id`, `Log` and the subcategory GUID in `Sub`.
     If needed, add your own `Filter = { param($d, $x) ... }` (`$d` — EventData fields, `$x` — event XML)
     and a `WMatch` string to search for in Wazuh.
   - Add the group name to the `ValidateSet` of `-Skip`.
3. Run the linter: `Invoke-ScriptAnalyzer -Path . -Settings ./PSScriptAnalyzerSettings.psd1`.
   It also runs automatically in GitHub Actions (`.github/workflows/lint.yml`).

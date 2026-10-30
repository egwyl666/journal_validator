# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project rules

- Documentation (README and any other docs) is written only in English (`README.md`) and Ukrainian (`README.uk.md`). Never write documentation in Russian. Keep both files in sync.
- All `*.ps1` scripts must stay ASCII-only.
- `RV-Validation.ps1` never changes the system permanently; persistent changes go only to `RV-Remediate.ps1` (backup, `-WhatIf`, `-Restore`).

## What this repository is

Two PowerShell scripts for Windows hosts monitored by Wazuh (Windows PowerShell 5.1 compatible,
run as Administrator). `RV-Validation.ps1` generates harmless test events, looks for them in the
local event logs, checks the Wazuh agent and optionally the delivery to the Wazuh indexer.
`RV-Remediate.ps1` applies agreed persistent fixes. The rules that consume these events live in a
separate repository (`egwyl666/wazarules`); this one only proves the telemetry exists.
README.md is the user guide (parameters, output columns, exit codes); keep its tables in sync with
`param(...)`.

## Commands

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1   # the CI job (.github/workflows/lint.yml), must be empty
```

```bash
LC_ALL=C grep -nP '[^\x00-\x7F]' *.ps1   # ASCII check, must print nothing
```

There are no unit tests; a change is proved by running the script on a Windows test host
(`-Only <group>` to run one test group, `-WhatIf` for `RV-Remediate.ps1`).

## How RV-Validation.ps1 is built

- `$tests` lists the expected events (`Id`, `Log`, audit subcategory GUID in `Sub`, generator name
  in `Gen`, optional `Filter = { param($d, $x) ... }` and `WMatch` for the indexer search).
  `$actions` maps each generator name to `Do` (creates the event) and an optional `Undo`
  (removes what `Do` created). `Undo` runs in `finally`, so test objects disappear even on an
  error or Ctrl+C. A new test needs both entries plus the group name in the `ValidateSet` of `-Skip`.
- Audit policy is read with `auditpol` by subcategory GUID, so the script works on any OS language.
- The agent checks parse `ossec.conf` and the group `shared\agent.conf` by wrapping them in a
  `<root>` element (an agent `ossec.conf` can contain several `<ossec_config>` blocks).
- Exit codes: `0` all found, `1` something MISSING, `2` not Administrator (`Exit-Script` keeps the
  console open when run as a scriptblock one-liner).

## How RV-Remediate.ps1 is built

Without switches it only makes a backup and runs the validation. Each switch is one persistent
change; every change is backed up to `backup-<time>` first, `-WhatIf` prints instead of changing,
`-Restore <folder>` rolls back. `-FixAgentConfig` restarts the agent and rolls back by itself when
the agent does not reconnect within 90 s (exit code `3`). At the end it runs `RV-Validation.ps1`
from the same folder, from `-OutDir`, or downloaded from GitHub.

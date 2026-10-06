# Project rules

- Documentation (README and any other docs) is written only in English (`README.md`) and Ukrainian (`README.uk.md`). Never write documentation in Russian. Keep both files in sync.
- All `*.ps1` scripts must stay ASCII-only.
- `RV-Validation.ps1` never changes the system permanently; persistent changes go only to `RV-Remediate.ps1` (backup, `-WhatIf`, `-Restore`).

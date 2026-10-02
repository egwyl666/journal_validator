# RV-Validation

Скрипт для контрольной проверки Windows-хоста после закрытия пробелов в аудите.
Он генерирует тестовые события, ищет их в локальных журналах, проверяет агент Wazuh
и (по желанию) доставку событий в индексатор Wazuh. Все созданные объекты (служба,
задача, правило файрвола, локальный пользователь) удаляются сразу, даже если шаг упал
или запуск прерван через Ctrl+C.

Результаты сохраняются в `C:\SOC_Audit\RV-validation-<host>-<time>.txt` (лог) и `.csv` (таблица).

## Быстрый запуск (одна строка)

Нужен PowerShell, **запущенный от имени администратора**.

Скачать и сразу выполнить, ничего не сохраняя на диск:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1)))
```

С флагами (их дописывают в конец строки):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1))) -TimeoutSec 60 -Skip share -PsStats
```

Из `cmd.exe` или «Выполнить» (Win+R). Сначала скачивает файл в `%TEMP%`, затем запускает:

```cmd
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; irm https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1 -OutFile $env:TEMP\RV-Validation.ps1; & $env:TEMP\RV-Validation.ps1"
```

Обычный запуск из скачанного файла:

```powershell
powershell -ExecutionPolicy Bypass -File .\RV-Validation.ps1
```

> Если на Windows PowerShell 5.1 `irm` падает с ошибкой TLS, выполните перед ним
> `[Net.ServicePointManager]::SecurityProtocol='Tls12'`.

## Параметры

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-OutDir <path>` | `C:\SOC_Audit` | Папка для `.txt` и `.csv` |
| `-TimeoutSec <5-600>` | `30` | Сколько ждать события в локальных журналах |
| `-Skip <groups>` | — | Пропустить группы тестов: `cmd`, `logon`, `service`, `task`, `firewall`, `share`, `user` |
| `-PsStats` | выкл. | Топ Event ID в `PowerShell/Operational` за 24 ч (может занять несколько минут) |
| `-IndexerUrl <url>` | — | URL индексатора Wazuh (OpenSearch), например `https://10.0.0.5:9200`. Без него доставка в Wazuh не проверяется |
| `-IndexerCredential <cred>` | — | Учётка индексатора: `-IndexerCredential (Get-Credential)` |
| `-AgentName <name>` | имя хоста | `agent.name` в Wazuh, если он отличается от имени компьютера |
| `-WazuhWaitSec <0-1800>` | `120` | Сколько ждать алерты в индексаторе |
| `-SkipCertificateCheck` | выкл. | Принять самоподписанный сертификат индексатора |

Пример со сквозной проверкой доставки в Wazuh:

```powershell
.\RV-Validation.ps1 -IndexerUrl https://wazuh-indexer:9200 -IndexerCredential (Get-Credential) -SkipCertificateCheck
```

> В `wazuh-alerts-*` попадают только события, на которые сработало правило. `MISSING` в
> колонке `Wazuh` при `OK` в `Local` означает одно из двух: событие не доставлено или для
> него нет правила.

## Что проверяется

| Группа | Действие | Event ID | Подкатегория аудита |
|---|---|---|---|
| `cmd` | `cmd /c echo <marker>` | 4688 (+ проверка CommandLine) | Process Creation |
| `logon` | неверный пароль для `rv_fake_user` | 4625, 4776 | Logon, Credential Validation |
| `service` | `sc create` / `sc delete` | 4697, 7045 | Security System Extension |
| `task` | `schtasks /create` / `/delete` | 4698, 4699 | Other Object Access Events |
| `firewall` | `New-` / `Remove-NetFirewallRule` | 4946, 4948 | MPSSVC Rule-Level Policy Change |
| `share` | `dir \\127.0.0.1\C$` | 5140 | File Share |
| `user` | создание / удаление локального пользователя `rv_NNNNNN` | 4720, 4726 | User Account Management |

Перед тестами скрипт показывает текущую политику аудита (`auditpol` по GUID, поэтому работает
на любом языке ОС) и состояние ключа `ProcessCreationIncludeCmdLine_Enabled`. По ним сразу видно,
почему какое-то событие отсутствует.

## Результат

- Колонки CSV: `Test, EventID, Log, Local, LocalFound, LocalTime, RecordId, AuditPolicy, Before, After, Note, Wazuh`.
- `Local`: `OK` / `MISSING` / `SKIPPED`. `Wazuh`: `OK (rule N)` / `MISSING` / `ERROR`; пусто, если индексатор не задан.
- Коды возврата: `0` — всё найдено, `1` — есть `MISSING`, `2` — запуск без прав администратора.
  Если скрипт запущен однострочником через scriptblock, код кладётся в `$LASTEXITCODE`, а консоль не закрывается.

## Как добавить свой флаг или тест

1. **Флаг.** Добавьте параметр в блок `param(...)` в начале скрипта:
   ```powershell
   [switch]$NoCleanup,                          # переключатель
   [ValidateRange(1, 10)][int]$Repeat = 1,      # число с проверкой диапазона
   [ValidateSet('a', 'b')][string[]]$Only = @() # список допустимых значений
   ```
   Затем используйте `$NoCleanup` / `$Repeat` в коде и добавьте строку в таблицу параметров выше.
2. **Новый тест.**
   - В `$actions` добавьте генератор: `Do` создаёт событие, `Undo` (если нужен) удаляет созданное.
     `Undo` всегда выполняется в `finally`.
   - В `$tests` добавьте ожидаемое событие с тем же `Gen`, а также `Id`, `Log`, GUID подкатегории в `Sub`.
     При необходимости добавьте свой `Filter = { param($d, $x) ... }` (`$d` — поля EventData, `$x` — XML события)
     и строку `WMatch` для поиска в Wazuh.
   - Добавьте имя группы в `ValidateSet` параметра `-Skip`.
3. Прогоните линтер: `Invoke-ScriptAnalyzer -Path . -Settings ./PSScriptAnalyzerSettings.psd1`.
   В GitHub Actions он запускается автоматически (`.github/workflows/lint.yml`).

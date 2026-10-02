# RV-Validation

[English](README.md) | **Українська**

Скрипт для контрольної перевірки Windows-хоста після закриття прогалин в аудиті.
Він генерує тестові події, шукає їх у локальних журналах, перевіряє агент Wazuh
і (за бажанням) доставку подій до індексатора Wazuh. Усі створені об'єкти (служба,
завдання, правило брандмауера, локальний користувач) видаляються одразу, навіть якщо
крок завершився помилкою або запуск перервано через Ctrl+C.

Результати зберігаються в `C:\SOC_Audit\RV-validation-<host>-<time>.txt` (лог) та `.csv` (таблиця).

## Швидкий запуск (один рядок)

Потрібен PowerShell, **запущений від імені адміністратора**.

Завантажити й одразу виконати, нічого не зберігаючи на диск:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1)))
```

З прапорцями (їх дописують у кінець рядка):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1))) -TimeoutSec 60 -Skip share -PsStats
```

З `cmd.exe` або «Виконати» (Win+R). Спочатку завантажує файл у `%TEMP%`, потім запускає:

```cmd
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; irm https://raw.githubusercontent.com/egwyl666/journal_validator/main/RV-Validation.ps1 -OutFile $env:TEMP\RV-Validation.ps1; & $env:TEMP\RV-Validation.ps1"
```

Звичайний запуск із завантаженого файлу:

```powershell
powershell -ExecutionPolicy Bypass -File .\RV-Validation.ps1
```

> Якщо у Windows PowerShell 5.1 `irm` падає з помилкою TLS, спершу виконайте
> `[Net.ServicePointManager]::SecurityProtocol='Tls12'`.

## Параметри

| Прапорець | За замовчуванням | Опис |
|---|---|---|
| `-OutDir <path>` | `C:\SOC_Audit` | Тека для `.txt` та `.csv` |
| `-TimeoutSec <5-600>` | `30` | Скільки чекати події в локальних журналах |
| `-Skip <groups>` | — | Пропустити групи тестів: `cmd`, `logon`, `service`, `task`, `firewall`, `share`, `user` |
| `-PsStats` | вимк. | Топ Event ID у `PowerShell/Operational` за 24 год (може тривати кілька хвилин) |
| `-IndexerUrl <url>` | — | URL індексатора Wazuh (OpenSearch), наприклад `https://10.0.0.5:9200`. Без нього доставка до Wazuh не перевіряється |
| `-IndexerCredential <cred>` | — | Обліковий запис індексатора: `-IndexerCredential (Get-Credential)` |
| `-AgentName <name>` | ім'я хоста | `agent.name` у Wazuh, якщо воно відрізняється від імені комп'ютера |
| `-WazuhWaitSec <0-1800>` | `120` | Скільки чекати алерти в індексаторі |
| `-SkipCertificateCheck` | вимк. | Приймати самопідписаний сертифікат індексатора |

Приклад із наскрізною перевіркою доставки до Wazuh:

```powershell
.\RV-Validation.ps1 -IndexerUrl https://wazuh-indexer:9200 -IndexerCredential (Get-Credential) -SkipCertificateCheck
```

> У `wazuh-alerts-*` потрапляють лише події, на які спрацювало правило. `MISSING` у колонці
> `Wazuh` при `OK` у `Local` означає одне з двох: подію не доставлено або для неї немає правила.

## Що перевіряється

| Група | Дія | Event ID | Підкатегорія аудиту |
|---|---|---|---|
| `cmd` | `cmd /c echo <marker>` | 4688 (+ перевірка CommandLine) | Process Creation |
| `logon` | неправильний пароль для `rv_fake_user` | 4625, 4776 | Logon, Credential Validation |
| `service` | `sc create` / `sc delete` | 4697, 7045 | Security System Extension |
| `task` | `schtasks /create` / `/delete` | 4698, 4699 | Other Object Access Events |
| `firewall` | `New-` / `Remove-NetFirewallRule` | 4946, 4948 | MPSSVC Rule-Level Policy Change |
| `share` | `dir \\127.0.0.1\C$` | 5140 | File Share |
| `user` | створення / видалення локального користувача `rv_NNNNNN` | 4720, 4726 | User Account Management |

Перед тестами скрипт показує поточну політику аудиту (`auditpol` за GUID, тому працює
на будь-якій мові ОС) і значення ключа `ProcessCreationIncludeCmdLine_Enabled`. За ними
одразу видно, чому якоїсь події немає.

## Результат

- Колонки CSV: `Test, EventID, Log, Local, LocalFound, LocalTime, RecordId, AuditPolicy, Before, After, Note, Wazuh`.
- `Local`: `OK` / `MISSING` / `SKIPPED`. `Wazuh`: `OK (rule N)` / `MISSING` / `ERROR`; порожньо, якщо індексатор не задано.
- Коди повернення: `0` — усе знайдено, `1` — є `MISSING`, `2` — запуск без прав адміністратора.
  Якщо скрипт запущено однорядковим варіантом через scriptblock, код записується в `$LASTEXITCODE`, а консоль не закривається.

## Як додати свій прапорець або тест

1. **Прапорець.** Додайте параметр у блок `param(...)` на початку скрипта:
   ```powershell
   [switch]$NoCleanup,                          # перемикач
   [ValidateRange(1, 10)][int]$Repeat = 1,      # число з перевіркою діапазону
   [ValidateSet('a', 'b')][string[]]$Only = @() # список допустимих значень
   ```
   Потім використовуйте `$NoCleanup` / `$Repeat` у коді й додайте рядок у таблицю параметрів вище.
2. **Новий тест.**
   - У `$actions` додайте генератор: `Do` створює подію, `Undo` (якщо потрібен) видаляє створене.
     `Undo` завжди виконується у `finally`.
   - У `$tests` додайте очікувану подію з тим самим `Gen`, а також `Id`, `Log` і GUID підкатегорії в `Sub`.
     За потреби додайте свій `Filter = { param($d, $x) ... }` (`$d` — поля EventData, `$x` — XML події)
     і рядок `WMatch` для пошуку у Wazuh.
   - Додайте назву групи у `ValidateSet` параметра `-Skip`.
3. Запустіть лінтер: `Invoke-ScriptAnalyzer -Path . -Settings ./PSScriptAnalyzerSettings.psd1`.
   У GitHub Actions він запускається автоматично (`.github/workflows/lint.yml`).

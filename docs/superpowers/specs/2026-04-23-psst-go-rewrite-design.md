# psst — Перепись на Go — Спецификация дизайна

**Дата:** 2026-04-23
**Статус:** Утверждено
**Цель:** Полный 1:1 перенос https://github.com/Michaelliv/psst (TypeScript/Bun) на Go
**Платформы:** Linux amd64 + arm64

## Обзор

psst — AI-ориентированный менеджер секретов. CLI-инструмент, позволяющий AI-агентам использовать секреты (API keys, passwords) без прямого доступа к их значениям. Секреты шифруются (AES-256-GCM), хранятся в SQLite vault, а ключ шифрования — в OS keychain.

Переписываем на Go для: единого бинарника без runtime-зависимостей, производительности, простоты дистрибуции.

## Архитектура

### Подход: Идиоматичный Go с интерфейсами и DI

Структура проекта:

```
psst/
├── cmd/
│   └── psst/
│       └── main.go              # точка входа: DI-связывание, вызов cobra
├── internal/
│   ├── cli/                     # cobra-команды
│   │   ├── root.go              # root + persistent flags
│   │   ├── init.go              # psst init
│   │   ├── set.go               # psst set
│   │   ├── get.go               # psst get
│   │   ├── list.go              # psst list / list envs
│   │   ├── rm.go                # psst rm
│   │   ├── run.go               # psst run
│   │   ├── exec.go              # psst SECRET -- cmd
│   │   ├── import.go            # psst import
│   │   ├── export.go            # psst export
│   │   ├── scan.go              # psst scan
│   │   ├── history.go           # psst history
│   │   ├── rollback.go          # psst rollback
│   │   └── tag.go               # psst tag/untag
│   ├── vault/                   # фасад бизнес-логики
│   │   ├── vault.go             # Vault struct (главная точка входа)
│   │   ├── types.go             # Secret, SecretMeta, SecretHistoryEntry и др.
│   │   └── vault_test.go
│   ├── store/                   # слой хранения
│   │   ├── store.go             # интерфейс SecretStore
│   │   ├── sqlite.go            # реализация SQLite
│   │   ├── migrations.go        # создание схемы + ALTER TABLE
│   │   └── sqlite_test.go
│   ├── crypto/                  # шифрование
│   │   ├── crypto.go            # интерфейс Encryptor
│   │   ├── aesgcm.go            # реализация AES-256-GCM
│   │   └── aesgcm_test.go
│   ├── keyring/                 # хранение ключа шифрования
│   │   ├── keyring.go           # интерфейс KeyProvider
│   │   ├── oskeyring.go         # zalando/go-keyring (libsecret на Linux)
│   │   ├── envvar.go            # fallback на PSST_PASSWORD env var
│   │   └── keyring_test.go
│   ├── runner/                  # выполнение подпроцессов
│   │   ├── runner.go            # Runner struct
│   │   ├── mask.go              # маскирование вывода
│   │   └── runner_test.go
│   └── output/                  # форматирование вывода
│       ├── output.go            # Formatter + режимы human/json/quiet
│       └── output_test.go
├── go.mod
├── go.sum
└── .gitignore
```

### DI-связывание (main.go)

```go
func main() {
    enc := crypto.NewAESGCM()
    kp := keyring.NewProvider()  // oskeyring с fallback на envvar
    store := store.NewSQLite(vaultPath)
    v := vault.New(enc, kp, store)
    r := runner.New()
    fmt := output.NewFormatter(jsonMode, quietMode)

    cli.Execute(v, r, fmt)
}
```

## Интерфейсы

### Encryptor (`internal/crypto/crypto.go`)

```go
type Encryptor interface {
    Encrypt(plaintext []byte) (ciphertext, iv []byte, err error)
    Decrypt(ciphertext, iv []byte) ([]byte, error)
    KeyToBuffer(key string) ([]byte, error)
}
```

### KeyProvider (`internal/keyring/keyring.go`)

```go
type KeyProvider interface {
    GetKey(service, account string) ([]byte, error)
    SetKey(service, account string, key []byte) error
    IsAvailable() bool
    GenerateKey() ([]byte, error)
}
```

### SecretStore (`internal/store/store.go`)

```go
type StoredSecret struct {
    Name           string
    EncryptedValue []byte
    IV             []byte
    Tags           []string
    CreatedAt      string
    UpdatedAt      string
}

type SecretMeta struct {
    Name      string
    Tags      []string
    CreatedAt string
    UpdatedAt string
}

type HistoryEntry struct {
    Version  int
    Tags     []string
    ArchivedAt string
}

type SecretStore interface {
    InitSchema() error
    GetSecret(name string) (*StoredSecret, error)
    SetSecret(name string, encValue, iv []byte, tags []string) error
    DeleteSecret(name string) error
    DeleteHistory(name string) error
    ListSecrets() ([]SecretMeta, error)
    GetHistory(name string) ([]HistoryEntry, error)
    AddHistory(name string, version int, encValue, iv []byte, tags []string) error
    PruneHistory(name string, keepVersions int) error
    Close() error
}
```

### Formatter (`internal/output/output.go`)

```go
type Formatter interface {
    Success(msg string)
    Error(msg string)
    Warning(msg string)
    Bullet(msg string)
    SecretList(secrets []vault.SecretMeta)
    SecretValue(name, value string)
    History(name string, current *vault.Secret, entries []vault.SecretHistoryEntry)
    ScanResult(results []runner.ScanResult)
    JSON(data any) error
}
```

## Криптография (AES-256-GCM)

**Пакет:** `internal/crypto/`
**Реализация:** `crypto/aes` + `crypto/cipher` + `crypto/rand` (stdlib)

### Константы
- Длина ключа: 32 байта (AES-256)
- Длина IV: 12 байт (стандартный GCM)

### KeyToBuffer(key string) ([]byte, error)
1. Попробовать base64 decode -> если результат ровно 32 байта, использовать напрямую
2. Иначе: SHA-256 хеш строки -> использовать как ключ

### Encrypt(plaintext []byte) (ciphertext, iv []byte, err error)
1. Генерация случайного 12-байтового IV через `crypto/rand`
2. Создание AES cipher block из ключа
3. Создание GCM mode (`cipher.NewGCM`)
4. Seal: `gcm.Seal(nil, iv, plaintext, nil)`
5. Возврат ciphertext + iv

### Decrypt(ciphertext, iv []byte) ([]byte, error)
1. Создание AES cipher block из ключа
2. Создание GCM mode
3. Open: `gcm.Open(nil, iv, ciphertext, nil)`
4. Возврат plaintext

## Схема SQLite

**Пакет:** `internal/store/`
**Драйвер:** `github.com/mattn/go-sqlite3`

### Таблица: secrets

```sql
CREATE TABLE IF NOT EXISTS secrets (
    name TEXT PRIMARY KEY,
    encrypted_value BLOB NOT NULL,
    iv BLOB NOT NULL,
    created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    updated_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    tags TEXT DEFAULT '[]'
);
```

### Таблица: secrets_history

```sql
CREATE TABLE IF NOT EXISTS secrets_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    encrypted_value BLOB NOT NULL,
    iv BLOB NOT NULL,
    tags TEXT DEFAULT '[]',
    archived_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    UNIQUE(name, version)
);

CREATE INDEX IF NOT EXISTS idx_secrets_history_name ON secrets_history(name);
```

### Миграции

Выполняются при каждом `InitSchema()`:
1. `CREATE TABLE IF NOT EXISTS` для обеих таблиц (идемпотентно)
2. Проверить наличие колонки `tags` в `secrets` через `PRAGMA table_info` -> если нет, `ALTER TABLE secrets ADD COLUMN tags TEXT DEFAULT '[]'`
3. То же для `secrets_history`

## Keyring

**Пакет:** `internal/keyring/`
**Библиотека:** `github.com/zalando/go-keyring`

### Реализации KeyProvider

#### oskeyring (Linux)
- `GetKey`: `keyring.Get(service, account)` -> base64 decode -> 32 байта
- `SetKey`: base64 encode -> `keyring.Set(service, account, encoded)`
- `IsAvailable`: попробовать `keyring.Get("psst", "test")`, проверить ошибку
- `GenerateKey`: `crypto/rand` -> 32 байта -> base64

#### envvar (fallback)
- `GetKey`: прочитать `PSST_PASSWORD` из env -> `KeyToBuffer()`
- `SetKey`: no-op (env var только для чтения)
- `IsAvailable`: `os.Getenv("PSST_PASSWORD") != ""`

### Выбор провайдера
```go
func NewProvider() KeyProvider {
    os := &OSKeyring{}
    if os.IsAvailable() {
        return os
    }
    return &EnvVarProvider{}
}
```

### Константы
- Service: `"psst"`
- Account: `"vault-key"`

## Vault (Фасад)

**Пакет:** `internal/vault/`

### Типы

```go
type Secret struct {
    Name      string
    Value     string    // расшифрованное значение
    Tags      []string
    CreatedAt string
    UpdatedAt string
}

type SecretMeta struct {
    Name      string
    Tags      []string
    CreatedAt string
    UpdatedAt string
}

type SecretHistoryEntry struct {
    Version    int
    Tags       []string
    ArchivedAt string
}
```

### Структура Vault

```go
type Vault struct {
    enc    crypto.Encryptor
    kp     keyring.KeyProvider
    store  store.SecretStore
    key    []byte
    open   bool
}
```

### Ключевые методы

- `New(enc, kp, store) *Vault`
- `Init(opts InitOptions) error` — создать директорию, инициализировать схему, сгенерировать ключ, сохранить в keychain
- `Unlock() error` — получить ключ из keychain/PSST_PASSWORD
- `SetSecret(name, value string, tags []string) error` — архивировать текущее в history, зашифровать, сохранить
- `GetSecret(name string) (*Secret, error)` — прочитать, расшифровать
- `ListSecrets() ([]SecretMeta, error)`
- `DeleteSecret(name string) error` — удалить секрет + историю
- `GetHistory(name string) ([]SecretHistoryEntry, error)`
- `Rollback(name string, version int) error` — архивировать текущее, восстановить версию
- `AddTag(name, tag string) error`
- `RemoveTag(name, tag string) error`
- `GetSecretsByTags(tags []string) ([]SecretMeta, error)` — логика OR
- `GetAllSecrets() ([]Secret, error)` — расшифровать все (для run/export)
- `Close()`

### Обнаружение vault

```go
func FindVaultPath(global bool, env string) (string, error)
```

Приоритет:
1. Если `--global`: `~/.psst/` (или `~/.psst/envs/<name>/`)
2. Если `--env`: `.psst/envs/<name>/` (local) или `~/.psst/envs/<name>/` (global)
3. По умолчанию: `.psst/` в текущей директории

## Runner (Выполнение подпроцессов)

**Пакет:** `internal/runner/`

### Exec (именованные секреты)

```go
func (r *Runner) Exec(secrets map[string]string, command string, args []string, opts ExecOptions) (int, error)
```

1. Построить env: `os.Environ()` + карта секретов - `PSST_PASSWORD`
2. Раскрыть `$VAR` и `${VAR}` в аргументах используя карту секретов
3. `exec.Command(command, expandedArgs...)`
4. Установить `cmd.Env`
5. Если `opts.MaskOutput`: перенаправить stdout/stderr через маскирование, иначе inherit
6. Дождаться завершения, вернуть exit code

### Run (все секреты)

Аналогично Exec, но секреты из `vault.GetAllSecrets()`.

### Маскирование вывода

```go
func MaskSecrets(text string, secrets []string) string {
    for _, s := range secrets {
        if len(s) > 0 {
            text = strings.ReplaceAll(text, s, "[REDACTED]")
        }
    }
    return text
}
```

Применяется к потокам stdout/stderr в реальном времени.

### Раскрытие переменных окружения

```go
func ExpandEnvVars(arg string, env map[string]string) string
```

Заменяет паттерны `$NAME` и `${NAME}` на значения из карты env.

## CLI-команды

**Пакет:** `internal/cli/`
**Фреймворк:** `github.com/spf13/cobra`

### Корневая команда

Persistent flags:
- `--json` / `-j`: JSON-вывод
- `--quiet` / `-q`: Тихий режим
- `--global` / `-g`: Глобальный vault
- `--env <name>`: Имя окружения
- `--tag <name>` (повторяемый): Фильтр по тегу

Резервные env vars: `PSST_GLOBAL`, `PSST_ENV`

### Список команд

| Команда | Описание |
|---------|----------|
| `psst init [--global] [--env <name>]` | Создать vault, сгенерировать ключ, сохранить в keychain |
| `psst set <name> [--stdin] [--tag <t>]...` | Установить секрет (интерактивный ввод или stdin) |
| `psst get <name>` | Вывести расшифрованное значение |
| `psst list [envs] [--tag <t>]...` | Список имён секретов (или окружений) |
| `psst rm <name>` | Удалить секрет + историю |
| `psst run <command> [args...]` | Запустить со всеми секретами |
| `psst <SECRET>... -- <command> [args...]` | Запустить с конкретными секретами |
| `psst import [--stdin \| --from-env \| <file>]` | Импорт из .env/stdin/env |
| `psst export [--env-file <path>]` | Экспорт в .env формате |
| `psst scan [--staged] [--path <dir>]` | Сканер утечек секретов в файлах |
| `psst history <name>` | Показать историю версий |
| `psst rollback <name> --to <version>` | Восстановить предыдущую версию |
| `psst tag <name> <tag>` | Добавить тег секрету |
| `psst untag <name> <tag>` | Удалить тег у секрета |

### Обработка exec-паттерна

Паттерн `psst SECRET1 SECRET2 -- command args` требует парсинга до cobra:
1. Найти индекс `--` в аргументах
2. Всё до `--` = имена секретов (или пусто, если есть теги)
3. Всё после `--` = команда + аргументы
4. Передать в `exec.go`

## Форматирование вывода

**Пакет:** `internal/output/`

Три режима, управляемые флагами:
- **Human** (по умолчанию): цветной вывод, Unicode-символы (✓, ✗, ●)
- **JSON** (`--json`): `encoding/json` маршализация
- **Quiet** (`--quiet`): минимальный вывод, только exit codes

Цвета: ANSI escape codes напрямую (без библиотеки, только Linux).

## Коды возврата

```go
const (
    ExitSuccess    = 0  // Успех
    ExitError      = 1  // Ошибка
    ExitUserError  = 2  // Ошибка пользователя
    ExitNoVault    = 3  // Vault не найден
    ExitAuthFailed = 5  // Ошибка аутентификации
)
```

## Сканер секретов

**Пакет:** `internal/runner/` (или `internal/cli/scan.go`)

### Алгоритм:
1. Получить все расшифрованные секреты из vault
2. Собрать список файлов: git tracked, staged или конкретный путь
3. Для каждого файла:
   - Пропускать бинарные (проверка на null byte)
   - Пропускать файлы > 1MB
   - Пропускать нетекстовые расширения
   - Для каждого секрета (len >= 4): `strings.Contains(content, secretValue)`
4. Отчёт: filename:line -> какой секрет найден

### Тип результата сканирования:
```go
type ScanResult struct {
    File    string
    Line    int
    Secret  string  // имя секрета, не значение
}
```

## Импорт/Экспорт

### Импорт
- Парсинг `.env` файлов: `KEY=VALUE` с обработкой кавычек (одинарные, двойные, без кавычек)
- `--stdin`: чтение из stdin
- `--from-env`: чтение из `os.Environ()`
- Валидация имён: `^[A-Z][A-Z0-9_]*$`

### Экспорт
- Запись в формате `KEY=VALUE` в stdout или файл
- Экранирование значений с пробелами/спецсимволами

## Окружения (Environments)

- Vault по умолчанию: `.psst/vault.db` (local) или `~/.psst/vault.db` (global)
- Именованное окружение: `.psst/envs/<name>/vault.db` или `~/.psst/envs/<name>/vault.db`
- `psst list envs`: сканирование local и global на наличие env-директорий
- `PSST_ENV` env var как fallback для `--env`

## История и откат

- При каждом `SetSecret`: архивировать текущее значение в `secrets_history` с инкрементальным version
- Автообрезка: хранить последние 10 версий
- `Rollback(name, version)`: архивировать текущее (как новую версию), затем восстановить указанную версию
- Откат обратим (текущее значение никогда не теряется)

## Теги

- Хранятся как JSON-массив в колонке `tags` TEXT
- `AddTag` / `RemoveTag`: прочитать JSON, модифицировать, записать обратно
- Фильтрация по тегам с логикой OR: секрет подходит, если есть ХОТЯ БЫ ОДИН из запрошенных тегов

## Зависимости

```
github.com/spf13/cobra        # CLI-фреймворк
github.com/mattn/go-sqlite3   # SQLite-драйвер (CGo)
github.com/zalando/go-keyring # Интеграция с OS keychain
```

Используемые пакеты stdlib:
- `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256` — шифрование
- `encoding/base64`, `encoding/json` — кодирование
- `os/exec` — выполнение подпроцессов
- `database/sql` — интерфейс SQLite
- `fmt`, `text/template` — форматирование вывода

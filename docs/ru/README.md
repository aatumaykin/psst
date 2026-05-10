# psst

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev/)

**[Documentation in English](../../README.md)**

Менеджер секретов для AI-агентов. Агенты используют секреты, не видя их значений.

Переписано на Go из [Michaelliv/psst](https://github.com/Michaelliv/psst) (оригинал на TypeScript/Bun).

## Зачем

Когда вы вставляете API-ключи в контекст AI-агента, они попадают в:

- Контекстное окно модели
- Историю терминала
- Лог-файлы
- Скриншоты

psst внедряет секреты в окружение подпроцесса при запуске. Агент управляет, psst обрабатывает секреты.

```
# Агент пишет:
psst STRIPE_KEY -- curl -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com

# Что видит агент:
# ✓ Команда выполнена успешно

# Что выполнилось на самом деле:
# curl -H "Authorization: Bearer sk_live_abc123..." https://api.stripe.com
```

## Установка

### Из исходников

```bash
git clone https://github.com/aatumaykin/psst.git && cd psst
make build
sudo install psst /usr/local/bin/
```

### Требования

- Go 1.26+ (для сборки)
- На Linux: заголовки `libsecret` (для поддержки OS keyring)

## Быстрый старт

```bash
# Создать vault (ключ шифрования сохраняется в OS keychain)
psst init

# На сервере без OS keychain — использовать PSST_PASSWORD:
export PSST_PASSWORD="your-password"
psst init                    # создаст vault с ключом из пароля

# Добавить секреты
echo "sk-live-abc123" | psst set STRIPE_KEY --stdin
echo "postgres://db:5432/app" | psst set DATABASE_URL --stdin
psst set API_KEY                    # интерактивный ввод

# Проверить
psst list

# Использовать с агентом
psst STRIPE_KEY -- curl -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com
psst run -- ./deploy.sh             # внедрить все секреты
```

> **Важно:** На Linux без `libsecret` (серверы, CI) ключ нельзя сохранить в OS keychain.
> Используйте `PSST_PASSWORD` — его нужно задавать перед каждым запуском:
> ```bash
> export PSST_PASSWORD="your-password"
> psst init
> psst set KEY --stdin <<< "value"
> psst list
> ```

## Команды

### Управление секретами

```bash
psst init [--global] [--env <name>] [--vault-path <path>]   # Создать vault
psst set <NAME> [--stdin] [--tag T]   # Добавить/обновить секрет
psst get <NAME>                       # Показать значение (только интерактивный терминал)
psst verify <NAME> --expected <val>   # Проверить значение без раскрытия
psst verify <NAME> --hash <sha256>    # Проверить по SHA-256 хешу
psst list [--tag T]                   # Список имён секретов
psst rm <NAME>                        # Удалить секрет + историю
psst migrate                          # Обновить vault до последней версии KDF
psst completion <shell>               # Генерация скрипта автодополнения
```

### Использование секретов

```bash
psst run <команда> [аргументы...]        # Запустить со всеми секретами
psst <СЕКРЕТ>... -- <команда> [аргументы] # Запустить с конкретными секретами
```

### Импорт / Экспорт

```bash
psst import .env                      # Импорт из .env файла
psst import --stdin                   # Импорт из stdin
psst import --from-env                # Импорт из переменных окружения
psst export                           # Экспорт в stdout (только интерактивный терминал)
psst export --env-file .env           # Экспорт в файл
```

### История и откат

```bash
psst history <NAME>                   # Посмотреть историю версий (последние 10)
psst rollback <NAME> --to <версия>    # Восстановить предыдущую версию
```

### Теги

```bash
psst tag <NAME> <TAG>                 # Добавить тег
psst untag <NAME> <TAG>               # Удалить тег
psst list --tag prod                  # Фильтр по тегу (логика OR)
psst --tag aws -- aws s3 ls           # Запустить только с тегированными секретами
```

### Автообновление

```bash
psst update check                     # Проверить наличие обновления
psst update install                   # Скачать и установить последнюю версию
psst update install --force           # Переустановить текущую версию
```

### Сканер утечек

```bash
psst scan                             # Проверить git-отслеживаемые файлы
psst scan --staged                    # Только staged файлы
psst scan --path ./src                # Конкретная директория
```

Проверяет файлы на наличие реальных значений секретов из vault — нет ложных срабатываний на regex.

### Окружения (Environments)

```bash
psst init --env prod                  # Создать vault для "prod"
psst --env prod set API_KEY --stdin
psst --env prod list
psst --env prod API_KEY -- curl ...

psst list-envs                        # Список всех окружений
```

Хранятся в `.psst/envs/<name>/vault.db` (или `~/.psst/envs/<name>/` с `--global`).

### Произвольный путь к vault

Когда стандартное разрешение пути (локальный или глобальный) не подходит (например, cron-задачи или кастомная структура директорий), можно указать путь к директории vault напрямую. Файл vault всегда называется `vault.db`:

```bash
psst init --vault-path /opt/secrets
psst --vault-path /opt/secrets set API_KEY --stdin
psst --vault-path /opt/secrets list
psst --vault-path /opt/secrets API_KEY -- curl ...
```

`--vault-path` имеет приоритет над `--global` и `--env`.

### Глобальные флаги

Все команды поддерживают:

```
--json                 Структурированный JSON-вывод
-q, --quiet            Минимальный вывод
-g, --global           Использовать глобальный vault (~/.psst/)
--env <name>           Использовать конкретное окружение
--tag <name>           Фильтр по тегу (повторяемый, логика OR)
--vault-path <path>    Путь к файлу базы данных vault
--no-mask              Отключить маскирование вывода (для отладки)
```

Резервные переменные окружения: `PSST_GLOBAL=1`, `PSST_ENV=<name>`.

## Безопасность

- Секреты шифруются при хранении **AES-256-GCM**
- **Argon2id** KDF для парольных vaults (v2), SHA-256 для legacy (v1)
- Уникальный случайный IV при каждом шифровании
- Ключ шифрования хранится в OS keychain (libsecret на Linux)
- Секреты автоматически маскируются в выводе команд (`[REDACTED]`)
- Секреты никогда не попадают в контекст агента
- `psst get` и `psst export` требуют подтверждения в интерактивном терминале
- `psst verify` для безопасного сравнения секретов без раскрытия значений (constant-time)
- `PSST_PASSWORD` удаляется из окружения дочернего процесса
- Права на файл vault БД установлены в `0600`
- Best-effort обнуление ключей и plaintext в памяти

## CI / Работа без OS keychain

Когда OS keychain недоступен (серверы, Docker, CI), используйте `PSST_PASSWORD`:

```bash
export PSST_PASSWORD="your-password"   # задать один раз в сессии
psst init                              # создать vault
psst set API_KEY --stdin <<< "value"
psst run -- ./deploy.sh                # секреты внедряются в env, вывод маскируется
```

Ключ выводится из пароля через Argon2id (новые vaults) или SHA-256 (legacy, обновление через `psst migrate`). `PSST_PASSWORD` нужно задавать перед каждым использованием psst.

## Архитектура

```
cmd/psst/main.go          Точка входа (DI-связывание)
internal/
├── crypto/               Шифрование AES-256-GCM (интерфейс Encryptor)
├── store/                Хранение SQLite (интерфейс SecretStore)
├── keyring/              OS keychain + fallback на env var (интерфейс KeyProvider)
├── vault/                Фасад бизнес-логики
├── output/               Форматирование human/JSON/quiet
├── runner/               Выполнение подпроцессов + маскирование вывода
├── updater/              Механизм самообновления (GitHub releases)
├── version/              Информация о версии (ldflags)
└── cli/                  Cobra-команды (18 корневых команд + exec-паттерн)
```

### Ключевые интерфейсы

```go
type Encryptor interface {
    Encrypt(plaintext []byte, key []byte, aad ...[]byte) (ciphertext, iv []byte, err error)
    Decrypt(ciphertext, iv []byte, key []byte, aad ...[]byte) ([]byte, error)
    KeyToBuffer(key string) ([]byte, error)
    KeyToBufferV2WithSalt(key string, salt []byte) ([]byte, error)
    GenerateKey() ([]byte, error)
}

type KeyProvider interface {
    GetRawKey(service, account string) ([]byte, error)
    SetKey(service, account string, key []byte) error
    IsAvailable() bool
    GenerateKey() ([]byte, error)
}

type SecretStore interface {
    InitSchema() error
    GetSecret(ctx context.Context, name string) (*StoredSecret, error)
    GetAllSecrets(ctx context.Context) ([]StoredSecret, error)
    ListSecrets(ctx context.Context) ([]SecretMeta, error)
    SetSecret(ctx context.Context, name string, encValue, iv []byte, tags []string) error
    DeleteSecret(ctx context.Context, name string) error
    // ... (полный интерфейс в internal/store/store.go)
}
```

## Разработка

```bash
make build              # Собрать бинарник
make test               # Запустить все тесты
make clean              # Удалить бинарник

# Кросс-компиляция
make build-linux-amd64
make build-linux-arm64
```

### Зависимости

| Пакет | Назначение |
|-------|------------|
| `spf13/cobra` | CLI-фреймворк |
| `modernc.org/sqlite` | Pure Go SQLite-драйвер (без CGo) |
| `zalando/go-keyring` | Интеграция с OS keychain |
| `golang.org/x/term` | Безопасный ввод в терминале |
| `golang.org/x/crypto` | Argon2id KDF |

### Схема SQLite

```sql
CREATE TABLE vault_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE secrets (
    name TEXT PRIMARY KEY,
    encrypted_value BLOB NOT NULL,
    iv BLOB NOT NULL,
    created_at TEXT,
    updated_at TEXT,
    tags TEXT DEFAULT '[]'
);

CREATE TABLE secrets_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    encrypted_value BLOB NOT NULL,
    iv BLOB NOT NULL,
    tags TEXT DEFAULT '[]',
    archived_at TEXT,
    UNIQUE(name, version)
);
```

## Отличия от оригинала (TypeScript/Bun)

| Свойство | Оригинал (TS) | Здесь (Go) |
|----------|---------------|------------|
| Runtime | Bun | Статический бинарник |
| SQLite | bun:sqlite / better-sqlite3 | modernc.org/sqlite (pure Go) |
| Криптография | Web Crypto API | stdlib crypto/aes + crypto/cipher |
| Keychain | Вызов CLI-утилит | zalando/go-keyring |
| CLI | Ручной парсинг аргументов | spf13/cobra |
| Платформы | macOS, Linux, Windows | Linux (amd64, arm64) |
| SDK | Да (подключаемая библиотека) | Только CLI |

## Лицензия

[MIT](../../LICENSE)

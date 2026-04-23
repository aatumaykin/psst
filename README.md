# psst

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
git clone <url-репозитория> && cd psst
make build
sudo install psst /usr/local/bin/
```

### Требования

- Go 1.22+ (для сборки)
- gcc (для CGo — mattn/go-sqlite3)
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
psst init [--global] [--env <name>]   # Создать vault
psst set <NAME> [--stdin] [--tag T]   # Добавить/обновить секрет
psst get <NAME>                       # Показать значение (для отладки)
psst list [--tag T]                   # Список имён секретов
psst rm <NAME>                        # Удалить секрет + историю
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
psst export                           # Экспорт в stdout (.env формат)
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

### Глобальные флаги

Все команды поддерживают:

```
--json              Структурированный JSON-вывод
-q, --quiet         Минимальный вывод
-g, --global        Использовать глобальный vault (~/.psst/)
--env <name>        Использовать конкретное окружение
--tag <name>        Фильтр по тегу (повторяемый, логика OR)
```

Резервные переменные окружения: `PSST_GLOBAL=1`, `PSST_ENV=<name>`.

## Безопасность

- Секреты шифруются при хранении **AES-256-GCM**
- Уникальный случайный IV при каждом шифровании
- Ключ шифрования хранится в OS keychain (libsecret на Linux)
- Секреты автоматически маскируются в выводе команд (`[REDACTED]`)
- Секреты никогда не попадают в контекст агента
- `PSST_PASSWORD` удаляется из окружения дочернего процесса

## CI / Работа без OS keychain

Когда OS keychain недоступен (серверы, Docker, CI), используйте `PSST_PASSWORD`:

```bash
export PSST_PASSWORD="your-password"   # задать один раз в сессии
psst init                              # создать vault
psst set API_KEY --stdin <<< "value"
psst run -- ./deploy.sh                # секреты внедряются в env, вывод маскируется
```

Ключ выводится из пароля через SHA-256. `PSST_PASSWORD` нужно задавать перед каждым использованием psst.

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
└── cli/                  Cobra-команды (14 команд)
```

### Ключевые интерфейсы

```go
type Encryptor interface {
    Encrypt(plaintext, key []byte) (ciphertext, iv []byte, err error)
    Decrypt(ciphertext, iv, key []byte) ([]byte, error)
    KeyToBuffer(key string) ([]byte, error)
    GenerateKey() ([]byte, error)
}

type KeyProvider interface {
    GetKey(service, account string) ([]byte, error)
    SetKey(service, account string, key []byte) error
    IsAvailable() bool
    GenerateKey() ([]byte, error)
}

type SecretStore interface {
    InitSchema() error
    GetSecret(name string) (*StoredSecret, error)
    SetSecret(name string, encValue, iv []byte, tags []string) error
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
| `mattn/go-sqlite3` | SQLite-драйвер (CGo) |
| `zalando/go-keyring` | Интеграция с OS keychain |

### Схема SQLite

```sql
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
| SQLite | bun:sqlite / better-sqlite3 | mattn/go-sqlite3 |
| Криптография | Web Crypto API | stdlib crypto/aes + crypto/cipher |
| Keychain | Вызов CLI-утилит | zalando/go-keyring |
| CLI | Ручной парсинг аргументов | spf13/cobra |
| Платформы | macOS, Linux, Windows | Linux (amd64, arm64) |
| SDK | Да (подключаемая библиотека) | Только CLI |

## Лицензия

MIT

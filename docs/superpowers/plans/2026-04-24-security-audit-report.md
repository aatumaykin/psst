# psst — Аудит безопасности и качества кода

**Дата:** 2026-04-24  
**Версия:** main (HEAD)

## Сводка

| Категория     | CRITICAL | HIGH | MEDIUM | LOW |
| ------------- | -------- | ---- | ------ | --- |
| Безопасность  | 3        | 5    | 7      | 9   |
| Архитектура   | —        | 2    | 3      | —   |
| Качество кода | —        | 1    | 4      | 4   |
| Рефакторинг   | —        | —    | 3      | 5   |
| Тесты         | —        | —    | Покрытие ~40-45% | — |

---

## CRITICAL

### C-01. Слабая деривация ключа (SHA-256 без соли, без KDF)
- **Файл:** `internal/crypto/aesgcm.go:58-66`
- Один проход SHA-256 для деривации ключа из пароля. GPU-брутфорс — секунды.
- Нет соли — одинаковые пароли дают одинаковые ключи.
- **Fix:** Argon2id или PBKDF2 ≥600k итераций + случайная соль.

### C-02. Vault DB создаётся с дефолтным umask (world-readable)
- **Файл:** `internal/store/sqlite.go:17-23`
- `vault.db` читаем всеми пользователями системы.
- **Fix:** `os.Chmod(dbPath, 0600)` после создания.

### C-03. Маскировка ломается на границе 4KB буфера
- **Файл:** `internal/runner/runner.go:67-79`
- `streamWithMasking` читает по 4096 байт. Секрет на границе чанка не маскируется.
- **Fix:** Overlap-буфер размером `maxSecretLen - 1` или построчная обработка.

---

## HIGH

### Безопасность

| ID   | Файл                      | Проблема                                                                 |
| ---- | ------------------------- | ------------------------------------------------------------------------ |
| H-01 | `runner/mask.go:5-11`     | Нестабильный порядок маскировки (map iteration) — подстроки утекают      |
| H-02 | `runner/expand.go:8-22`   | `$NAME` без braces — частичная подстановка (`$API` внутри `$API_KEY`)    |
| H-03 | `cli/set.go:37-42`        | Интерактивный ввод эхоит секрет в терминал. Fix: `term.ReadPassword`     |
| H-04 | `cli/export.go:29`        | Экспортный файл с perms `0644`. Fix: `0600`                               |
| H-05 | `vault/vault.go:82`       | Ключ и plaintext не затираются в памяти                                  |

### Архитектура

| ID      | Файл                      | Проблема                                                            |
| ------- | ------------------------- | ------------------------------------------------------------------- |
| ARCH-01 | `keyring/*.go`            | keyring импортирует crypto (нарушение изоляции leaf-пакетов)        |
| ARCH-03 | `vault/vault.go:173-206`  | Rollback без транзакции + ошибка AddHistory проигнорирована         |

### Качество

| ID      | Файл                      | Проблема                                      |
| ------- | ------------------------- | --------------------------------------------- |
| QUAL-02 | `vault/vault.go:203`      | `AddHistory` — ошибка полностью проигнорирована |

---

## MEDIUM

### Безопасность
- **M-03** `store/migrations.go:45,67` — SQL через конкатенацию строк (не эксплуатируемо сейчас)
- **M-04** `cli/import.go:103-117` — `--from-env` импортирует все uppercase env vars
- **M-06** `vault/vault.go:173-206` — Rollback не в транзакции
- **M-07** `store/sqlite.go` — нет advisory lock для конкурентного доступа

### Архитектура
- **ARCH-02** `vault/types.go:17` — `type SecretMeta = store.SecretMeta` раскрывает store
- **ARCH-04** `store/sqlite.go:195-208` — `ExecTx`: data race на `s.tx`
- **ARCH-05** `cli/exec.go:39-41` — теряется exit code подпроцесса

### Качество
- **QUAL-01** `store/sqlite.go` — 6 мест: глушение `json.Unmarshal`/`time.Parse`
- **QUAL-04** `output/output.go:157-161` — ошибка `json.Encode` проигнорирована
- **QUAL-06** `cli/history.go:36` — ошибка `GetSecret` проигнорирована → nil dereference

### Рефакторинг
- **REFACT-01** — 11 CLI команд: дублирование vault-open паттерна
- **REFACT-02** — 4 метода store: дублирование парсинга tags/time
- **REFACT-06** `keyring/oskeyring.go:28-38` — `IsAvailable()` side effects

---

## LOW

- **L-01** `cli/args.go:42` — secret names matching `--env` value silently skipped
- **L-02** `vault/vault.go:279` — error messages include secret names
- **L-03** `cli/history.go:36` — decrypts secret that is never displayed
- **L-04** `cli/scan.go:60` — symlinks followed during scan
- **L-05** `cli/scan.go:99-103` — UTF-16 not handled
- **L-06** `cli/scan.go:122-132` — binary detection is extension-only
- **L-07** `cli/root.go:65-70` — PSST_GLOBAL/PSST_ENV silently override
- **L-08** `cli/get.go` — no name validation (unlike set)
- **L-09** `cli/run.go:40` — `--no-mask` without confirmation

---

## Тестовое покрытие: ~40-45%

### Критичные пробелы (P0)
1. `cli/` — 0 unit-тестов
2. `runner.Exec` — нет unit-теста с маскировкой
3. `cli/scan.go: scanFile` — нет теста
4. `cli/args.go: filterSecretNames` — нет тестов
5. Нет интеграционного теста маскированного вывода

### Критичные пробелы (P1)
6. `vault.FindVaultPath` — нет тестов
7. `vault.InitVault` — нет unit-тестов
8. `vault.Unlock` error path — не покрыт
9. `store.GetAllSecrets` — не покрыт
10. `store.ExecTx` rollback — не покрыт
11. `output` — JSON mode не протестирован

# Code Quality — psst

## Principles

- **KISS** — simple, readable code over clever abstractions.
- **DRY** — extract common patterns, but don't over-abstract.
- **YAGNI** — don't add features "just in case."
- **Explicit > Implicit** — prefer clear, direct code over magic.

## Code Style

### Formatting

- Use `gofmt` (default Go formatting).
- Tabs for indentation (Go convention).
- No line length limit, but keep lines readable.

### Naming

- **Packages:** lowercase, single word (`crypto`, `store`, `vault`, `runner`).
- **Types/Structs:** PascalCase (`SQLiteStore`, `AESGCM`, `KeyProvider`).
- **Interfaces:** PascalCase, often descriptive noun (`Encryptor`, `SecretStore`, `KeyProvider`).
- **Functions/Methods:** PascalCase (exported), camelCase (unexported).
- **Variables:** camelCase, short names in narrow scope (`enc`, `kp`, `s`, `v`).
- **Constants:** PascalCase for exported, camelCase for unexported (`serviceName`, `maxHistory`).
- **Secret names in CLI:** `UPPER_SNAKE_CASE` matching `^[A-Z][A-Z0-9_]*$`.
- **Test helpers:** `setupTestVault`, `setupTestStore`, `captureOutput`.

### File Organization

- One primary type/interface per file when reasonable.
- Interface definition in `<name>.go`, implementation in `<name>_impl.go` (e.g., `store.go` / `sqlite.go`).
- Test files: `<name>_test.go` in the same package.
- CLI commands: one file per command in `internal/cli/` (e.g., `init.go`, `set.go`, `scan.go`).

### Error Handling

- Return errors, never panic in library/business code.
- Wrap errors with context: `fmt.Errorf("open vault: %w", err)`.
- In CLI layer: use `exitWithError(msg)` for fatal errors.
- Exit codes: 0 (success), 1 (error), 3 (no vault), 5 (auth failed).

### Constructors

- Use `New*` functions: `NewAESGCM()`, `NewSQLite(path)`, `New(enc, kp, s)`.
- No builder pattern — pass dependencies directly.

### Comments

- Minimal comments. Code should be self-documenting.
- Doc comments on exported types and functions when non-obvious.
- No inline comments explaining obvious code.

## Anti-Patterns to Avoid

- Global mutable state (no `var` package-level maps/slices for state).
- Init functions in non-CLI packages (use explicit constructors).
- Loggers or telemetry in internal packages — output formatting belongs in `output/`.
- Direct SQL in `vault/` or `cli/` — all SQL stays in `store/`.
- Raw string concatenation for SQL — use parameterized queries (`?` placeholders).

## Refactoring Rules

- When adding a new CLI command: create `internal/cli/<command>.go`, register in `init()`.
- When adding a new store operation: add to `SecretStore` interface, implement in `sqlite.go`.
- When changing encryption: implement `Encryptor` interface, don't modify `AESGCM` methods in place.
- When adding output format: extend `Formatter`, don't scatter `fmt.Printf` across commands.

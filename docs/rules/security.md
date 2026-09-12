# Security — psst

This is a **security-critical** project — a secrets manager. Security rules apply to ALL changes without exception.

## Core Security Principles

1. **Agent never sees secret values.** The entire purpose of psst is to prevent AI agents from accessing plaintext secrets. Any change that leaks values to stdout, logs, or agent context is a critical bug.
2. **Defense in depth.** Secrets are encrypted at rest (AES-256-GCM), masked in output (`[REDACTED]`), and `PSST_PASSWORD` is stripped from child process environment.
3. **No secrets in code.** Never hardcode API keys, passwords, tokens, or connection strings.

## Secret Handling Rules

### In Code

- Secret values must only exist in memory within `vault.GetSecret()` → `crypto.Decrypt()` → `runner.Exec()` pipeline.
- Never log secret values. Never include them in error messages.
- `runner.MaskSecrets()` must mask ALL secret values in subprocess stdout/stderr.
- `PSST_PASSWORD` must be removed from child process environment (`buildEnv` in `runner/runner.go`).
- Use parameterized SQL queries — never interpolate values into SQL strings.

### In Tests

- Use fake/dummy values in tests (`"secret123"`, `"test-password"`).
- Never use real API keys, production passwords, or actual tokens in test fixtures.
- `vault_test.go` uses `testKeyProvider` — this pattern must be followed for new tests requiring key access.

### In Configuration

- `.env` and `.env.*` are in `.gitignore` — never commit them.
- `*.db` files are in `.gitignore` — vault databases must never be committed.
- Use `PSST_PASSWORD` env var for headless environments, never bake it into scripts.

## Output Masking

- `runner/mask.go` provides `MaskSecrets(text, secrets)` — replaces all secret values with `[REDACTED]`.
- The `--no-mask` flag exists for debugging but must never be default.
- `psst get <NAME>` reveals values — this is intentional for debugging. CLI warns about its purpose.

## Scanner (`psst scan`)

- Scans git-tracked files for actual vault secret values (exact match, not regex).
- Checks for binary file extensions and null bytes to avoid false positives.
- Skips files > 1MB for performance.
- Exit code 1 if leaks found — use in CI pre-commit hooks.

## Encryption

- AES-256-GCM with unique random 12-byte IV per encryption.
- Key derivation from password via SHA-256 (when OS keychain unavailable).
- OS keychain stores base64-encoded 32-byte key.
- Key never written to disk outside keychain.

## Git Storage

- One file per secret: `secrets/[tag/]NAME.enc` = base64(IV ‖ AES-256-GCM ciphertext).
- `psst.yaml` is untrusted input: strict validation, salt strictly immutable,
  KDF parameters only monotonically strengthened (pins in `.psst/config.yaml`).
- All git invocations run with `core.hooksPath=/dev/null`, `GIT_TERMINAL_PROMPT=0`,
  `GIT_CONFIG_NOSYSTEM=1`, an empty `GIT_CONFIG_GLOBAL`, and a subcommand allowlist.
- Git vaults derive keys strictly from the password via Argon2id — no base64
  passthrough, no OS keychain.
- A repo lock (`flock`) serializes all git mutations on a clone.

## What NOT To Do

- **Never** add a `--verbose` flag that prints secret values.
- **Never** cache decrypted values in package-level variables.
- **Never** expose secrets in JSON output unless explicitly requested via `psst get`.
- **Never** send plaintext secrets over network. The git remote of a git-storage vault contains only AES-256-GCM ciphertext (AAD-bound to vault metadata); secret names are visible as file names by design. The web UI (`psst serve`) binds to localhost by default and requires a mandatory
token plus a second vault-password unlock barrier; Host and Origin checks defend
against DNS rebinding/CSRF; values are revealed only through the dedicated
`/api/secrets/{name}/value` endpoint after unlock. Remote UI access only via SSH tunnel. Plaintext egress inventory: the child process environment (runner) is the existing channel; `psst render` (future phase) adds a 0600 file channel. `psst get` and `psst export` remain explicit operator-initiated exceptions.
- **Never** add telemetry or crash reporting that could include secret values.
- **Never** use `log.Printf` with secret-containing structs.
- **Never** store vault key in plaintext file.

## Web UI (`psst serve`)

- Default bind `127.0.0.1`; non-loopback `--listen` prints an explicit tunnel warning.
- Two barriers: server token (SHA-256 digest in memory, constant-time compare,
  printed once) and per-session vault unlock (Argon2id key in memory, 30-minute
  inactivity timeout, zeroed on logout/expiry/shutdown).
- Host allowlist (`127.0.0.1`/`localhost`/`[::1]` + listener port) on every request;
  `Origin` required and matching on every mutating request; cookie is `HttpOnly`,
  `SameSite=Strict`.
- Without unlock the UI serves only names/tags/dates/authors — never values.
- All vault/store access in the server serializes behind one mutex; the server is
  another client of the git clone (repo `flock` still guards cross-process).

## Vulnerability Response

If a security issue is found:

1. Do not file a public issue.
2. Report privately to the maintainer.
3. Fix must be reviewed before merge.
4. After fix, disclose via security advisory.

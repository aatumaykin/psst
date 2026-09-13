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
- `runner.MaskSecretsBytes()` must mask ALL secret values in subprocess stdout/stderr.
- `PSST_PASSWORD` must be removed from child process environment (`buildEnv` in `runner/runner.go`).
- Use parameterized SQL queries — never interpolate values into SQL strings.

### Memory Safety

- **Always use `[]byte` for secret values** — never convert to `string`. Go strings are immutable and cannot be zeroed; they persist in heap until GC.
- Zero all intermediate `[]byte` slices containing secret values after use with `zeroBytes()` or `crypto.ZeroBytes()`.
- In `runner/`, secret values are passed as `[][]byte` and zeroed after subprocess completes.
- In `cli/set.go`, password bytes are zeroed immediately after use.
- In `cli/scan.go`, secret values are kept as `[]byte` for comparison.
- After `Vault.MigrateKDF()`, the old encryption key is explicitly zeroed before replacement.

### Input Validation

- Secret names: max 256 bytes (`maxSecretNameLen` in `vault/vault.go`).
- Secret values: max 4096 bytes (`maxSecretValueLen` in `vault/vault.go`).
- Secret names must match `^[A-Z][A-Z0-9_]*$`.

### Brute-Force Protection

- Failed unlock attempts are tracked in `vault_meta` (`unlock_attempts` key).
- After `maxUnlockAttempts` (10) consecutive failures, the vault is temporarily locked.
- Lock duration increases with each cycle of failed attempts.
- Successful unlock resets the attempt counter.

Git-storage vaults keep no lockout counters (nothing secret-derived is committed on unlock); Argon2id is the brute-force defense for cloned ciphertext — wrong passwords fail at first decrypt.

### In Tests

- Use fake/dummy values in tests (`"secret123"`, `"test-password"`).
- Never use real API keys, production passwords, or actual tokens in test fixtures.
- `vault_test.go` uses `testKeyProvider` — this pattern must be followed for new tests requiring key access.

### In Configuration

- `.env` and `.env.*` are in `.gitignore` — never commit them.
- `*.db`, `*.db-wal`, `*.db-shm` are in `.gitignore` — vault databases and WAL sidecars must never be committed; `InitSchema` enforces 0600 on the db and on any existing `-wal`/`-shm` sidecars.
- Use `PSST_PASSWORD` env var for headless environments, never bake it into scripts.

## Output Masking

- `runner/mask.go` provides `MaskSecrets(text, secrets)` — replaces all secret values with `[REDACTED]`.
- The `--no-mask` flag exists for debugging but must never be default.
- `psst get <NAME>` reveals values — this is intentional for debugging. CLI warns about its purpose.

## Reveal Guard

- `psst get` and `psst export` (to stdout) require interactive terminal confirmation before revealing values.
- In non-TTY contexts (headless, pipes, AI agents), these commands are blocked with an error pointing to `psst verify`.
- `psst export --env-file` bypasses the guard — secrets are written to a file with `0600` permissions, not to stdout.
- Use `psst verify <name> --expected <value>` for safe comparison without revealing the secret.
- Use `psst verify <name> --hash <sha256>` for safer comparison (no plaintext in command history).
- `psst verify` uses constant-time comparison (`crypto/subtle.ConstantTimeCompare`) to prevent timing attacks.

## Scanner (`psst scan`)

- Scans git-tracked files for actual vault secret values (exact match, not regex).
- Checks for binary file extensions and null bytes to avoid false positives.
- Skips files > 1MB for performance.
- Exit code 1 if leaks found — use in CI pre-commit hooks.

## Encryption

- AES-256-GCM with unique random 12-byte IV per encryption.
- Key derivation from password via Argon2id (v2, current) or SHA-256 (v1, legacy). New vaults use Argon2id; upgrade via `psst migrate`.
- **Per-vault random salt** (16 bytes) generated during `init`, stored in `vault_meta.kdf_salt`. V2 vaults without `kdf_salt` are considered corrupted.
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
- Key rotation (`psst rotate`): new salt + re-encryption of every secret + updated
  `psst.yaml` as ONE commit; the rotating machine re-pins itself. Every other machine
  must adopt explicitly: `psst sync --accept-rotation` (password-verified probe before
  the pin moves) or a fresh clone. Unpushed local commits block acceptance (recovery:
  `psst sync` or `--discard-local`). Pre-rotation history stays fail-closed for rollback.

## What NOT To Do

- **Never** add a `--verbose` flag that prints secret values.
- **Never** cache decrypted values in package-level variables.
- **Never** expose secrets in JSON output unless explicitly requested via `psst get`.
- **Never** send plaintext secrets over network. The git remote of a git-storage vault contains only AES-256-GCM ciphertext (AAD-bound to vault metadata); secret names are visible as file names by design. The web UI (`psst serve`) binds to localhost by default and requires a mandatory
token plus a second vault-password unlock barrier; Host and Origin checks defend
against DNS rebinding/CSRF; values are revealed only through the dedicated
`/api/secrets/{name}/value` endpoint after unlock. Remote UI access only via SSH tunnel. Plaintext egress inventory: the child process environment (runner), the 0600 file produced by `psst render`, the web UI reveal (phase 2), and the explicit operator-initiated exceptions `psst get` / `psst export`.
- **Never** add telemetry or crash reporting that could include secret values.
- **Never** use `log.Printf` with secret-containing structs.
- **Never** store vault key in plaintext file.
- **Never** convert secret values to `string` — use `[]byte` and zero after use.
- **Never** use hardcoded or shared KDF salt — every vault must have a unique random salt.
- **Never** bypass `confirmReveal()` — if a new command reveals secret values, it must use the guard.

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

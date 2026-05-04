---
name: psst
description: Use when an AI agent needs to store, retrieve, or use secrets — API keys, tokens, passwords, connection strings. Use when building commands that require authentication or credentials, when managing secrets for CI/CD, or when a task involves sensitive values that must not leak into agent context, logs, or terminal history.
---

# psst — Secrets Manager for AI Agents

Encrypted vault (AES-256-GCM, SQLite). Agent manages secrets by **name only** — values are never exposed to agent context. Secrets are injected into subprocess environments at runtime, output is automatically masked with `[REDACTED]`.

## Cardinal Rule

**Never call `psst get` or `psst export`** — they are guarded by interactive terminal confirmation and will fail in non-TTY (agent) contexts. Use `psst verify` to check secret values without revealing them. All other commands are safe — they never reveal values.

## Secret Lifecycle

```bash
psst init [--global] [--env <name>]   # Create encrypted vault
psst set <NAME> [--stdin] [--tag T]   # Add/update secret (prompts if no --stdin)
psst list [--tag T]                   # List names only (no values)
psst rm <NAME>                        # Delete secret and its history
```

Secret names must match `^[A-Z][A-Z0-9_]*$` (e.g. `API_KEY`, `GITHUB_TOKEN`).

## Running Commands with Secrets — Critical Patterns

psst injects secrets as environment variables into a subprocess. The subprocess reads them from its env. **You must never pass `$VAR` to be expanded by the outer shell** — it will be empty because the outer shell doesn't have the secret.

### Exec Pattern: `psst KEY... -- <command>`

Injects **only specified secrets**. Everything before `--` is parsed as flags + secret names.

```bash
psst GITHUB_TOKEN -- sh -c 'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user'
```

### Run Command: `psst run -- <command>`

Injects **all** secrets from the vault. Use when a script or tool reads multiple env vars.

```bash
psst run -- ./deploy.sh
psst run -- terraform apply
```

### Tag Filtering: `psst --tag <T>... -- <command>`

Injects only secrets matching tags (OR logic, repeatable).

```bash
psst --tag aws -- aws s3 ls
```

### How Variable Expansion Works

```
Agent's shell  →  psst  →  subprocess
   ($)          inject     ($VAR expanded here
   empty!       into env    if using sh -c)
```

| Pattern | Works? | Why |
|---------|--------|-----|
| `psst KEY -- sh -c 'echo $KEY'` | Yes | Single quotes block outer shell; inner sh expands from injected env |
| `psst KEY -- printenv KEY` | Yes | Command reads env natively |
| `psst KEY -- curl -H "Auth: $KEY" url` | **No** | Double quotes → outer shell expands → empty string |
| `psst run -- ./script.sh` | Yes | Script reads env natively |

**Rules:**
1. If the command needs `$VAR` in arguments — wrap in `sh -c '...'` with **single quotes**
2. If the command reads env natively (scripts, tools like `terraform`, `aws`) — pass directly
3. Never use double quotes around `$VAR` — the outer shell will expand to empty

### `--expand-args` (escape hatch)

```bash
psst --expand-args GITHUB_TOKEN -- curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
```

psst itself expands `$VAR` in all arguments before exec. **Risks:** secret visible in `/proc/PID/cmdline`. Prefer `sh -c` with single quotes instead.

## Environments

```bash
psst init --env prod                    # Create named vault
psst --env prod list                    # Use prod vault
psst --env prod run -- ./deploy.sh      # Run with prod secrets
psst list-envs                          # List all environments
```

- Project vault: `.psst/vault.db`
- Global vault: `~/.psst/vault.db` (`--global` or `PSST_GLOBAL=1`)
- Named env: `.psst/envs/<name>/vault.db`

## Headless / CI Environments

When OS keychain is unavailable, set `PSST_PASSWORD` before each invocation:

```bash
export PSST_PASSWORD="your-password"
psst init
psst set API_KEY --stdin <<< "value"
psst run -- ./deploy.sh
```

`PSST_PASSWORD` is stripped from child process environment automatically.

## Tags

```bash
psst set AWS_KEY --stdin --tag aws
psst list --tag aws
psst --tag aws -- aws s3 ls
```

Tags use OR logic when multiple are specified.

## Import / Export

```bash
echo "value" | psst set API_KEY --stdin    # One secret
psst import .env                            # Bulk import from .env file
psst import --from-env                      # Import from current env vars
psst export --env-file .env                 # Export to file (safe)
psst export                                  # Export to stdout (requires terminal confirmation)
```

- `psst export` to stdout requires terminal confirmation — will fail for agents
- Use `psst export --env-file <path>` to write secrets to a file
- `psst import` does NOT delete the source `.env` — suggest cleanup after verification

## Verifying Secrets

```bash
psst verify API_KEY --expected "my-key"    # Check against expected value
psst verify API_KEY --hash <sha256_hex>    # Check against SHA-256 hash
```

- `--expected`: compares against plaintext. Warning: value visible in `/proc/PID/cmdline`
- `--hash`: compares against SHA-256 hex digest. Safer for terminal history
- Exit code: 0 = match, 1 = no match, 2 = error
- Uses constant-time comparison — no timing side-channels

## Leak Scanner

```bash
psst scan                # Check all git-tracked files for vault secret values
psst scan --staged       # Only staged files (pre-commit hook)
psst scan --path ./src   # Specific directory
```

Exact-match against real vault values — no regex false positives. Exit code 1 = leaks found.

## History & Rollback

```bash
psst history <NAME>                  # Show last 10 versions
psst rollback <NAME> --to <version>  # Restore previous version
```

## Quick Reference

| Situation | Command |
|-----------|---------|
| Add secret | `echo "value" \| psst set NAME --stdin` |
| List secrets | `psst list` |
| Run with specific secrets | `psst KEY1 KEY2 -- sh -c '...'` |
| Run with all secrets | `psst run -- ./script.sh` |
| API call with token | `psst TOKEN -- sh -c 'curl -H "Auth: Bearer $TOKEN" https://...'` |
| CI/headless | `PSST_PASSWORD=x psst run -- ./deploy.sh` |
| Check for leaks | `psst scan --staged` |
| Check secret value | `psst verify NAME --expected "val"` or `--hash <sha256>` |

## Agent Security Anti-Patterns

These mistakes leak secret values into agent context, logs, or terminal history:

| Anti-Pattern | Why It's Dangerous | Correct Approach |
|--------------|-------------------|----------------|
| `token=$(psst -g run -- printenv TOKEN)` | Secret value captured in agent context / shell variable | `psst -g run -- command-that-reads-env` |
| `psst run -- printenv TOKEN` | Secret printed to stdout — visible in logs and chat history | Never print secrets. Pass them via env to subprocess only |
| Writing secrets to temp files (`echo $TOKEN > /tmp/t`) | File persists on disk, readable by other processes | Use `psst run` to inject secrets directly into subprocess env |
| `git push https://$TOKEN@github.com/...` in open shell | Token expanded by shell → visible in shell history and ps | Use `psst -g run -- bash -c 'git push https://$TOKEN@github.com/...'` |
| Double quotes around `$VAR` | Empty string → auth failure | Use single quotes + `sh -c` |
| `psst run -- curl -H "$KEY" url` | Outer shell expands → empty | `psst KEY -- sh -c 'curl -H "$KEY" url'` |
| Using `psst get` | Blocked in non-TTY, requires confirmation in TTY | Use `psst verify` instead |
| `psst run` without `--` | `run` is a subcommand, not exec pattern | Always use `psst run -- command` |

**Rule for agents:** If you need a secret value in a command, always route it through `psst run` or `psst KEY -- command` so the subprocess reads it from its environment. Never extract the value into agent-visible variables, files, or output.

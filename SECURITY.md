# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

Security updates are applied to the latest release in the `0.x` line.

## Reporting a Vulnerability

**Do not file a public GitHub issue.**

To report a security vulnerability:

1. Use [GitHub Security Advisories](https://github.com/aatumaykin/psst/security/advisories/new) to privately disclose the issue.
2. Alternatively, contact the maintainer directly via email.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce or a proof of concept.
- Any suggested mitigations.

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Security Architecture

psst is a local-only secrets manager for AI agents. Key security properties:

- **Encryption at rest:** AES-256-GCM with unique 12-byte IV per secret.
- **Key derivation:** Argon2id KDF with per-vault random 16-byte salt. Legacy SHA-256 KDF is supported for migration only.
- **Output masking:** Secret values are replaced with `[REDACTED]` in subprocess stdout/stderr by default.
- **Memory safety:** Secret values are handled as `[]byte` and zeroed after use. No immutable `string` conversions.
- **Brute-force protection:** Failed unlock attempts are tracked; exponential lockout after repeated failures.
- **Local-only:** No network calls, no telemetry, no crash reporting. Secrets never leave the machine.

## Threat Model

psst defends against:

- AI agents accidentally reading secret values from stdout/logs.
- Plaintext secrets committed to version control (`psst scan`).
- Offline brute-force attacks on vault files (Argon2id KDF).
- Ciphertext swapping between secrets (AAD binding, planned).

psst does **not** defend against:

- A determined attacker with local code execution (memory can be dumped).
- Compromised OS keychain.
- Supply chain attacks on dependencies (use `govulncheck` and pin versions).

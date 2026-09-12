# `psst render` (Phase 3) Design

Date: 2026-09-12
Status: reviewed — round 1: 1 major / 7 minor / 1 nit, all addressed (fd-chmod before write, symlink policy, capped/deduped unresolved echo, inherited --tag flag, master-spec attribution reworded, grammar edges pinned: unterminated `${` and `$$KEY` literal, test gaps closed, recipes plaintext warnings, out==in pinning)
Scope: phase 3 of the git-storage master spec (`docs/superpowers/specs/2026-09-11-git-storage-webui-render-design.md` §3). Independent of phases 1–2: render is storage-agnostic (SQLite and git vaults alike) and adds no vault mutations. This document details §3 into a full implementation contract.

## Problem

Proxy-based secret injection covers only HTTP; generated script/config files with literal placeholders need a protocol-independent channel. `psst render` substitutes vault secrets into a template file and writes the result as a `0600` file — exactly one new plaintext egress channel, operator-initiated like `psst get`/`export` and the UI reveal (master spec §4).

## Decisions

| Decision | Choice |
|---|---|
| Package layout | New leaf package `internal/render` (pure byte-level matcher, zero internal imports); command wiring in `internal/cli/render.go` |
| Matcher | Own single-pass scanner; does NOT reuse `runner.ExpandEnvVars` (it re-scans the accumulated result — cascading substitution is exactly what render forbids) |
| Shell-name candidates | `$NAME` candidates are maximal `[A-Z0-9_]+` runs starting with `[A-Z]` (no prefix matching); the name-shape check `^[A-Z][A-Z0-9_]*$` applies to `${...}` inner text (a maximal run starting with `[A-Z]` trivially satisfies it — the check exists for the braced form, where inner text is arbitrary) |
| Brace syntax | ANY `{{...}}` span that does not resolve to a known secret is a hard error (fail-closed: a typo'd or lowercase `{{api_key}}` must never ship to prod) |
| Strict mode | `--strict` additionally makes unresolved `$`-candidates errors; documented trade-off — templates legitimately referencing non-psst env vars (`$HOME`) cannot use `--strict` |
| Escaping | None (non-goal; see §7) |
| Output | Full in-memory render, then a single write; on any hard error the output file contains zero rendered bytes (a pre-existing output file is untouched on the unresolved path — before the file is opened; on a chmod failure it is already truncated to zero by the open, but never contains plaintext) |
| File perms | `os.OpenFile(O_WRONLY|O_CREATE|O_TRUNC, 0600)` → **`f.Chmod(0600)` on the open file descriptor BEFORE any write** → single write → `Close`. Chmod-by-fd (not by path) cannot race a swapped symlink, and a chmod failure guarantees zero plaintext on disk; this also repairs a pre-existing wider file, which `O_CREAT 0600` alone cannot |
| Source | Whole vault, or `--tag` (repeatable, any-of semantics — consistent with `psst list --tag`) |
| stdout | Only the summary line; values never printed |

## 1. Placeholder grammar

Let `values` be the substitution set (secret name → plaintext bytes) built per §2, and `isName(s)` = `^[A-Z][A-Z0-9_]*$` (the existing `validName` shape).

1. `{{NAME}}` — **psst syntax, always resolved or the command fails.** The scanner finds the shortest `{{` … `}}` span. `inner` must satisfy `isName(inner)` AND `inner ∈ values`. Any `{{...}}` span whose inner fails either test is collected as unresolved-brace; when any exist, render fails listing every offender. This is an extension of §3's fail-closed rule ("never ship a literal `{{KEY}}` to prod"), ratified by this spec: Helm/Go-template constructs (`{{ .Values.x }}`) and lowercase typos (`{{api_key}}`) are hard errors, not pass-through — templates mixing another `{{ }}` templating system cannot be rendered (documented limitation, §4.3). Error output caps the echoed inner at its first 32 bytes plus `… (N bytes total)` — unresolved lists carry NAMES, never values, and unbounded template echo is a needless exposure. An unterminated `{{` with no closing `}}` is literal text (no span).
2. `$NAME` — bare shell syntax. On `$` followed by `[A-Z]`, consume the maximal `[A-Z0-9_]+` run as the candidate. If `candidate ∈ values` → substitute; otherwise the original bytes stay literal (non-strict) or the candidate is collected as unresolved-shell (strict). Maximal-run rule: in `$API_KEY`, the candidate is `API_KEY` — if only `API` exists in the vault, nothing is substituted (prefix matching is forbidden; matches shell semantics).
3. `${NAME}` — braced shell syntax. Inner must satisfy `isName` and membership, else literal (non-strict) / unresolved-shell (strict). `${VAR:-default}`-style defaults are NOT supported: the inner text fails `isName`, so non-strict leaves the whole span literal and `--strict` collects it as unresolved-shell (error) — same treatment as any other non-name inner. An unterminated `${` with no closing `}` is literal text (parallel to rule 1).
4. A `$` followed by anything else (`$1`, `$`, `$$`, `$lower`, `$_x`) is literal — including `$$KEY`, which stays `$$KEY` verbatim (the `$` consumed by the `$$` literal does not start a fresh candidate).
5. **Single pass.** Substituted values are copied into the output and never re-scanned: a secret value containing `$OTHER`, `${OTHER}` or `{{OTHER}}` lands in the output verbatim.

## 2. Substitution set construction

- Without `--tag`: `v.GetAllSecrets()` → map name → value.
- With `--tag` (repeatable): `v.GetSecretsByTags(tags)` (any-of) → `v.GetSecret(name)` per result. Names outside the filtered set are treated as absent: `{{OUTSIDE}}` → hard error, `$OUTSIDE` → literal (non-strict).
- The vault is opened through the standard read path `getUnlockedVault` (TTY prompt / `PSST_PASSWORD` / keychain; git vaults get the §1.3 best-effort pull and stale-clone warnings for free). Read-only: no store mutations.

## 3. CLI contract

```
psst render --in deploy.env.tpl --out deploy.env [--tag prod]... [--strict]
```

- Inherits the global persistent flags (`--env`, `--global`, `--storage`, `--tag`, `--json`, `--quiet`). `--tag` is the existing root persistent flag consumed via `getGlobalFlags` exactly like `psst list` (repeatable, any-of) — render defines NO flag of its own named `tag`.
- `--in` and `--out` are required local flags; `--strict` is a local bool flag. `--in` must exist. If `filepath.Abs` + `filepath.Clean` of `--out` equals that of `--in` → error `refusing to overwrite the template` (exit 1; symlink/hardlink aliases of the same file are undetected and accepted). `--out -` is rejected with `--out - is not supported: values must not go to stdout`. No stdin modes.
- Order of operations: read template → build values → render in memory → on unresolved (always for braces; with `--strict` also for shell) → `exitWithError` listing deduplicated names in first-occurrence order, each tagged with its syntax (`API_KEY ({{...}})`, `HOME ($...)`), exit 1, **no file written** → else `os.OpenFile(out, O_WRONLY|O_CREATE|O_TRUNC, 0600)` → `f.Chmod(0600)` (failure = hard error, zero bytes written) → single `f.Write` → `f.Close` → summary via `f.Success` (non-quiet) → `v.Close()`.
- Summary text: `Rendered N placeholders → <out>` (the formatter supplies the `✓` prefix and handles `--json`/`--quiet`). `N` counts every substitution across all three syntaxes.
- Exit codes follow the project convention: 0 success, 1 errors, 3 no vault, 5 auth (the latter two already handled inside `getUnlockedVault`).
- Error wrapping `fmt.Errorf("...: %w", err)`; no comments in code; conventional commit `feat: psst render command`.

## 4. Interface changes (complete list)

1. New package `internal/render`:
   - `type Syntax uint8` with `const (SyntaxBrace Syntax = iota; SyntaxShell)`.
   - `type Unresolved struct { Name string; Syntax Syntax }`. The returned `unresolved` slice is deduplicated and in first-occurrence order (the CLI formats it into the error; the 32-byte echo cap is CLI-side formatting, not matcher behavior).
   - `func Render(tmpl []byte, values map[string][]byte) (out []byte, unresolved []Unresolved, substitutions int)` — pure function, byte-level, no internal imports.
2. New command `internal/cli/render.go` (`renderCmd`, local flags `--in`, `--out`, `--strict`; `--tag` comes from the inherited persistent flag; registered in `init()`).
3. Documentation (same PR): `docs/rules/security.md` egress inventory gains the render 0600-file channel (master spec §4 line becomes present tense); `docs/rules/architecture.md` gains the `render/` leaf row and `cli → render` dependency; `README.md` + `docs/ru/README.md` gain the render section and the recipes block (`ssh + sshpass -e`, python `os.environ`, node, `docker --env-file`). The recipes block carries two mandatory warnings: templates mixing another `{{ }}` templating system (Helm, Go templates) cannot be rendered — every `{{...}}` span must resolve; and rendered outputs are untracked plaintext — add them to `.gitignore` (only `.env`/`.env.*` are ignored by default; `psst scan` catches tracked leaks once committed).
4. No vault/store/server changes; no new dependencies; `go.mod` untouched.

## 5. Security review points

- Values exist in memory only inside the render call and the write buffer; never logged, never on stdout, never in error messages (unresolved lists contain NAMES with a 32-byte-capped echo, never values).
- The output file is the one new plaintext channel; 0600 is enforced by fd-chmod BEFORE the single write; failure to chmod is a hard error with zero bytes written.
- A symlinked `--out` is followed (the target is truncated and chmod'd 0600) — accepted for a local operator-run CLI, matching the existing `export --env-file` behavior (same-uid attackers can read the 0600 output anyway).
- render performs no vault writes; on git vaults it follows the read protocol (best-effort pull, fail-closed metadata checks inherited from the store).
- Templates are untrusted input only in the sense that they are scanned for placeholders; malformed content fails closed (brace syntax) or passes through literally (shell syntax).

## 6. Testing

Standard `testing`, fake values only, `PSST_NO_KEYCHAIN=1` (via `make test`).

`internal/render/render_test.go` (table-driven, pure function):
- Each syntax resolves: `{{KEY}}`, `$KEY`, `${KEY}`.
- Single-pass property: value of `A` containing `$B`, `${B}`, `{{B}}` lands verbatim; no cascading.
- Maximal run: `$API_KEY` with only `API` in values → literal; with `API_KEY` → substituted.
- Boundaries: `$KEY` inside `$KEY_LONGER` not substituted when scanning the longer candidate; `$` at EOF; `$$`; `$$KEY` stays verbatim; `$1`; `$lower`; unclosed `{{`; unclosed `${` literal; `${VAR:-x}` literal; `${MISSING}` non-strict → literal; empty inner `{{}}` → unresolved-brace error; `{{api_key}}` → unresolved-brace; unresolved list deduplicated, first-occurrence order, echo capped at 32 bytes.
- Counts: multiple placeholders, repeated same name.
- Byte preservation: invalid-UTF-8 value bytes round-trip; template bytes outside placeholders untouched.
- Unresolved reporting: braces always; shell only flagged (caller decides strictness).

`tests/render_test.go` (integration, existing binary pattern):
- Happy path: init vault, set 2 secrets (fake values), template mixing all syntaxes → exit 0, file content exact, stdout summary contains the expected `N`, values absent from stdout.
- Perms: pre-create `--out` with 0644 → after render mode is 0600 (chmod repair proven).
- Unresolved brace (`{{MISSING}}`) → exit 1, error contains `MISSING` (and the fake value NOWHERE in stderr/stdout), output file not created (and a pre-existing output file byte-identical).
- `--strict` with `$HOME` → exit 1; without `--strict` → `$HOME` literal in output, exit 0.
- `--tag` filter: secret outside tag set → `{{OUT}}` errors / `$OUT` literal.
- `--out` == `--in` → refused; `--out -` → refused with the stdout message.
- Git vault: one test with `--storage git` (init git vault pattern from `tests/git_storage_test.go`) → render works through the git read path.

## 7. Non-goals

- No escape syntax (`\{{`, `$$` are not escapes; `$` handling is §1.4).
- No stdin input / stdout output modes.
- No shell-default expansion (`${VAR:-default}` unsupported).
- No re-rendering/cascading — single pass is the contract.
- Not a template engine: no conditionals, loops, or filters.

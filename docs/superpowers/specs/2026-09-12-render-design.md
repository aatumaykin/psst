# `psst render` (Phase 3) Design

Date: 2026-09-12
Status: draft (pending subagent review)
Scope: phase 3 of the git-storage master spec (`docs/superpowers/specs/2026-09-11-git-storage-webui-render-design.md` §3). Independent of phases 1–2: render is storage-agnostic (SQLite and git vaults alike) and adds no vault mutations. This document details §3 into a full implementation contract.

## Problem

Proxy-based secret injection covers only HTTP; generated script/config files with literal placeholders need a protocol-independent channel. `psst render` substitutes vault secrets into a template file and writes the result as a `0600` file — exactly one new plaintext egress channel, operator-initiated like `psst get`/`export` and the UI reveal (master spec §4).

## Decisions

| Decision | Choice |
|---|---|
| Package layout | New leaf package `internal/render` (pure byte-level matcher, zero internal imports); command wiring in `internal/cli/render.go` |
| Matcher | Own single-pass scanner; does NOT reuse `runner.ExpandEnvVars` (it re-scans the accumulated result — cascading substitution is exactly what render forbids) |
| Shell-name candidates | `$NAME`/`${NAME}` candidates are maximal `[A-Z0-9_]+` runs starting with `[A-Z]` and must fully match the psst name shape `^[A-Z][A-Z0-9_]*$`; no prefix matching |
| Brace syntax | ANY `{{...}}` span that does not resolve to a known secret is a hard error (fail-closed: a typo'd or lowercase `{{api_key}}` must never ship to prod) |
| Strict mode | `--strict` additionally makes unresolved `$`-candidates errors; documented trade-off — templates legitimately referencing non-psst env vars (`$HOME`) cannot use `--strict` |
| Escaping | None (non-goal; see §7) |
| Output | Full in-memory render, then a single write; on any hard error the output file is never written (a pre-existing output file stays untouched) |
| File perms | `O_WRONLY|O_CREATE|O_TRUNC` with 0600, then an explicit `os.Chmod(path, 0600)` — chmod failure is an error; this repairs a pre-existing wider file, which `O_CREAT 0600` alone cannot |
| Source | Whole vault, or `--tag` (repeatable, any-of semantics — consistent with `psst list --tag`) |
| stdout | Only the summary line; values never printed |

## 1. Placeholder grammar

Let `values` be the substitution set (secret name → plaintext bytes) built per §2, and `isName(s)` = `^[A-Z][A-Z0-9_]*$` (the existing `validName` shape).

1. `{{NAME}}` — **psst syntax, always resolved or the command fails.** The scanner finds the shortest `{{` … `}}` span. `inner` must satisfy `isName(inner)` AND `inner ∈ values`. Any `{{...}}` span whose inner fails either test is collected as unresolved-brace; when any exist, render fails listing every offender (its inner text verbatim). Consequences, accepted by the master spec: Helm/Go-template constructs (`{{ .Values.x }}`) and lowercase typos (`{{api_key}}`) are hard errors, not pass-through — fail-closed beats mixed-template friendliness. An unterminated `{{` with no closing `}}` is literal text (no span).
2. `$NAME` — bare shell syntax. On `$` followed by `[A-Z]`, consume the maximal `[A-Z0-9_]+` run as the candidate. If `candidate ∈ values` → substitute; otherwise the original bytes stay literal (non-strict) or the candidate is collected as unresolved-shell (strict). Maximal-run rule: in `$API_KEY`, the candidate is `API_KEY` — if only `API` exists in the vault, nothing is substituted (prefix matching is forbidden; matches shell semantics).
3. `${NAME}` — braced shell syntax. Inner must satisfy `isName` and membership, else literal (non-strict) / unresolved-shell (strict). `${VAR:-default}`-style defaults are NOT supported and stay literal (§7).
4. A `$` followed by anything else (`$1`, `$`, `$$`, `$lower`, `$_x`) is literal.
5. **Single pass.** Substituted values are copied into the output and never re-scanned: a secret value containing `$OTHER`, `${OTHER}` or `{{OTHER}}` lands in the output verbatim.

## 2. Substitution set construction

- Without `--tag`: `v.GetAllSecrets()` → map name → value.
- With `--tag` (repeatable): `v.GetSecretsByTags(tags)` (any-of) → `v.GetSecret(name)` per result. Names outside the filtered set are treated as absent: `{{OUTSIDE}}` → hard error, `$OUTSIDE` → literal (non-strict).
- The vault is opened through the standard read path `getUnlockedVault` (TTY prompt / `PSST_PASSWORD` / keychain; git vaults get the §1.3 best-effort pull and stale-clone warnings for free). Read-only: no store mutations.

## 3. CLI contract

```
psst render --in deploy.env.tpl --out deploy.env [--tag prod]... [--strict]
```

- Inherits the global flags (`--env`, `--global`, `--storage`, `--json`, `--quiet`).
- `--in` and `--out` are required. `--in` must exist. If `--out` resolves to the same path as `--in` → error `refusing to overwrite the template` (exit 1). No stdin/stdout modes: `--out -` is rejected with the same message pattern — values must never reach stdout.
- Order of operations: read template → build values → render in memory → on unresolved (always for braces; with `--strict` also for shell) → `exitWithError("unresolved placeholders: API_KEY ({{...}}), HOME ($...)")` exit 1, **no file written** → else write output, `Close`, `os.Chmod(out, 0600)` (failure = error) → print `✓ Rendered N placeholders → <out>` (non-quiet) → `v.Close()`.
- `N` counts every substitution across all three syntaxes.
- Exit codes follow the project convention: 0 success, 1 errors, 3 no vault, 5 auth (the latter two already handled inside `getUnlockedVault`).
- Error wrapping `fmt.Errorf("...: %w", err)`; no comments in code; conventional commit `feat: psst render command`.

## 4. Interface changes (complete list)

1. New package `internal/render`:
   - `type Syntax uint8` with `const (SyntaxBrace Syntax = iota; SyntaxShell)`.
   - `type Unresolved struct { Name string; Syntax Syntax }`.
   - `func Render(tmpl []byte, values map[string][]byte) (out []byte, unresolved []Unresolved, substitutions int)` — pure function, byte-level, no internal imports.
2. New command `internal/cli/render.go` (`renderCmd`, flags `--in`, `--out`, `--tag` (StringArray), `--strict`; registered in `init()`).
3. Documentation (same PR): `docs/rules/security.md` egress inventory gains the render 0600-file channel (master spec §4 line becomes present tense); `docs/rules/architecture.md` gains the `render/` leaf row and `cli → render` dependency; `README.md` + `docs/ru/README.md` gain the render section and the recipes block (`ssh + sshpass -e`, python `os.environ`, node, `docker --env-file`).
4. No vault/store/server changes; no new dependencies; `go.mod` untouched.

## 5. Security review points

- Values exist in memory only inside the render call and the write buffer; never logged, never on stdout, never in error messages (unresolved lists contain NAMES, not values).
- The output file is the one new plaintext channel; 0600 enforced by write + chmod; failure to chmod is a hard error.
- render performs no vault writes; on git vaults it follows the read protocol (best-effort pull, fail-closed metadata checks inherited from the store).
- Templates are untrusted input only in the sense that they are scanned for placeholders; malformed content fails closed (brace syntax) or passes through literally (shell syntax).

## 6. Testing

Standard `testing`, fake values only, `PSST_NO_KEYCHAIN=1` (via `make test`).

`internal/render/render_test.go` (table-driven, pure function):
- Each syntax resolves: `{{KEY}}`, `$KEY`, `${KEY}`.
- Single-pass property: value of `A` containing `$B`, `${B}`, `{{B}}` lands verbatim; no cascading.
- Maximal run: `$API_KEY` with only `API` in values → literal; with `API_KEY` → substituted.
- Boundaries: `$KEY` inside `$KEY_LONGER` not substituted when scanning the longer candidate; `$` at EOF; `$$`; `$1`; `$lower`; unclosed `{{`; `${VAR:-x}` literal; empty inner `{{}}` → unresolved-brace error; `{{api_key}}` → unresolved-brace.
- Counts: multiple placeholders, repeated same name.
- Byte preservation: invalid-UTF-8 value bytes round-trip; template bytes outside placeholders untouched.
- Unresolved reporting: braces always; shell only flagged (caller decides strictness).

`tests/render_test.go` (integration, existing binary pattern):
- Happy path: init vault, set 2 secrets (fake values), template mixing all syntaxes → exit 0, file content exact, stdout has summary, values absent from stdout.
- Perms: pre-create `--out` with 0644 → after render mode is 0600 (chmod repair proven).
- Unresolved brace (`{{MISSING}}`) → exit 1, error lists name, output file not created (and a pre-existing output file byte-identical).
- `--strict` with `$HOME` → exit 1; without `--strict` → `$HOME` literal in output, exit 0.
- `--tag` filter: secret outside tag set → `{{OUT}}` errors / `$OUT` literal.
- `--out` == `--in` → refused.
- Git vault: one test with `--storage git` (init git vault pattern from `tests/git_storage_test.go`) → render works through the git read path.

## 7. Non-goals

- No escape syntax (`\{{`, `$$` are not escapes; `$` handling is §1.4).
- No stdin input / stdout output modes.
- No shell-default expansion (`${VAR:-default}` unsupported).
- No re-rendering/cascading — single pass is the contract.
- Not a template engine: no conditionals, loops, or filters.

# Go 1.26 Modernization + Scanner + Integration Tests

## Goal

Modernize codebase to Go 1.26, fix cross-platform scanner issues, add integration tests for all CLI commands.

## 1. Go 1.26 Modernization

Update `go.mod` to `go 1.26.0`. Apply modern stdlib features throughout:

- `slices.SortFunc` replaces custom `byLengthDesc` sort in `runner/expand.go`
- `slices.Contains` replaces manual search loops
- `maps.Keys` / `maps.Values` replace manual map iteration
- Built-in `min` / `max` where applicable
- `range over int` for numeric loops where cleaner

## 2. Cross-platform Scanner

Fix `scanFile` in `internal/cli/scan.go`:
- Skip UTF-8 BOM (`\xEF\xBB\xBF`) at start of first line
- Normalize `\r\n` → `\n` before secret matching via `strings.TrimRight(line, "\r")`

## 3. Integration Tests

Create `tests/integration_test.go` in separate `tests` package:
- `TestMain` builds `./psst` binary, sets `PSST_PASSWORD` env
- Each test uses temp dir, runs commands via `exec.Command`, asserts output/exit code
- Cover all 14 CLI commands: init, set, get, list, rm, run, import, export, history, rollback, tag, untag, scan, list-envs

## Files Changed

| File | Changes |
|------|---------|
| `go.mod` | Update to go 1.26.0 |
| `internal/runner/expand.go` | Use slices.SortFunc |
| `internal/cli/scan.go` | BOM + CRLF handling |
| `internal/store/sqlite.go` | slices.Contains where applicable |
| `internal/vault/vault.go` | Modern patterns |
| `tests/integration_test.go` (new) | Full CLI integration tests |

## Verification

- `make test` passes
- `go vet ./...` clean
- No new dependencies

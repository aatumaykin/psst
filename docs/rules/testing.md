# Testing — psst

## Testing Framework

- Standard Go `testing` package — no external testing frameworks (`testify`, `gocheck`, etc.).
- Run: `go test ./... -v` or `make test`.

## Test Organization

- Tests live alongside code: `<name>_test.go` in the same package.
- Package-level tests (not `*_test` package suffix) — tests access unexported functions.

## Patterns

### Test Helpers

Use `t.Helper()` in setup functions:

```go
func setupTestVault(t *testing.T) *Vault {
    t.Helper()
    // ...
}
```

Use `t.TempDir()` for temporary files (auto-cleaned):

```go
dir := t.TempDir()
dbPath := filepath.Join(dir, "vault.db")
```

Use `t.Cleanup()` for resource cleanup:

```go
t.Cleanup(func() { s.Close() })
```

### Table-Driven Tests

For functions with multiple input/output cases:

```go
tests := []struct {
    input, want string
}{
    {"$API_KEY", "secret123"},
    {"${API_KEY}", "secret123"},
}
for _, tt := range tests {
    got := ExpandEnvVars(tt.input, env)
    if got != tt.want {
        t.Errorf("ExpandEnvVars(%q) = %q, want %q", tt.input, got, tt.want)
    }
}
```

### Test Doubles

Implement interfaces for testing (no mock frameworks):

```go
type testKeyProvider struct {
    enc *crypto.AESGCM
    key []byte
}

func (t *testKeyProvider) GetKey(service, account string) ([]byte, error) {
    return t.key, nil
}
// ... implement other interface methods
```

### Output Capture

For testing output formatters:

```go
func captureOutput(fn func()) string {
    old := os.Stdout
    r, w, _ := os.Pipe()
    os.Stdout = w
    fn()
    w.Close()
    os.Stdout = old
    var buf bytes.Buffer
    buf.ReadFrom(r)
    return buf.String()
}
```

## Naming Conventions

- Test functions: `Test<UnitOfWork>_<Scenario>` or `Test<FunctionName>`.
- Examples: `TestSetGetSecret`, `TestEncryptDecryptRoundTrip`, `TestMaskSecretsEmpty`.

## Coverage Expectations

- All packages with business logic (`crypto`, `store`, `vault`, `runner`, `keyring`) must have tests.
- `cli/` commands are harder to unit test (they call `os.Exit`) — prefer integration testing via the built binary.
- `output/` tests verify formatting modes (human, JSON, quiet).

## What to Test

- **Happy path:** valid inputs produce expected outputs.
- **Error cases:** invalid inputs, missing resources, wrong keys.
- **Edge cases:** empty values, max-length names, concurrent access (SQLite WAL mode).
- **Security:** masking works for all secret values, `PSST_PASSWORD` stripped from env.
- **Round-trips:** encrypt → decrypt, set → get, set → history → rollback.

## Security Tests

These test categories are mandatory for any change touching encryption, vault, or runner:

- **Key zeroing:** verify old key bytes are zeroed after `MigrateKDF`.
- **Input limits:** verify rejection of names > 256 bytes and values > 4096 bytes.
- **Brute-force protection:** verify vault locks after 10 failed unlock attempts.
- **Masking boundary:** verify secrets split across stream chunks are fully masked.
- **Memory safety:** verify no immutable `string` conversions for secret values in runner/scan paths.
- **Corrupted vault:** verify graceful error when `kdf_salt` is missing for V2 vault.

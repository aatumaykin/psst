# Security & Quality Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all CRITICAL and HIGH security vulnerabilities, resolve architecture violations, improve code quality, and expand test coverage for the psst secrets manager.

**Architecture:** Changes are organized into 6 phases by priority. Phase 1–3 are security-critical. Phase 4 is architecture. Phase 5 is quality/refactoring. Phase 6 is test coverage. Each phase produces working, testable code.

**Tech Stack:** Go 1.26, Cobra, SQLite (mattn/go-sqlite3), zalando/go-keyring, golang.org/x/term (new dep for H-03), golang.org/x/crypto (new dep for Argon2id, C-01)

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `internal/crypto/aesgcm.go` | Modify | Add Argon2id KDF alongside SHA-256 (C-01) |
| `internal/store/migrations.go` | Modify | Add vault_meta table (C-01) |
| `internal/store/sqlite.go` | Modify | File permissions (C-02), scan helper (QUAL-01), ExecTx fix (ARCH-04) |
| `internal/runner/runner.go` | Modify | Overlap buffer in streamWithMasking (C-03), sort secrets (H-01) |
| `internal/runner/mask.go` | Modify | Sort secrets by descending length |
| `internal/runner/expand.go` | Modify | Fix `$NAME` word boundary (H-02) |
| `internal/cli/set.go` | Modify | Use term.ReadPassword (H-03) |
| `internal/cli/export.go` | Modify | File permissions 0600 (H-04) |
| `internal/cli/exec.go` | Modify | Propagate exit code (ARCH-05) |
| `internal/cli/history.go` | Modify | Fix nil dereference (QUAL-06), avoid unnecessary decrypt (L-03) |
| `internal/cli/init.go` | Modify | Use Formatter for warnings (QUAL-08) |
| `internal/cli/args.go` | Modify | Fix `--env` skip logic (L-01) |
| `internal/cli/scan.go` | Modify | Symlink check (L-04), validate migration table names (M-03) |
| `internal/cli/get.go` | Modify | Add name validation (L-08) |
| `internal/cli/import.go` | Modify | Change `*os.File` to `io.Reader` (REFACT-05) |
| `internal/vault/vault.go` | Modify | Rollback in tx (ARCH-03), memory zeroing (H-05) |
| `internal/vault/types.go` | Modify | Remove type alias (ARCH-02) |
| `internal/keyring/keyring.go` | Modify | Accept Encryptor interface (ARCH-01) |
| `internal/keyring/oskeyring.go` | Modify | Accept Encryptor interface (ARCH-01) |
| `internal/keyring/envvar.go` | Modify | Accept Encryptor interface (ARCH-01) |
| `internal/output/output.go` | Modify | Fix printJSON error (QUAL-04), fix HistoryEntries sig (REFACT-07) |
| `internal/store/migrations.go` | Modify | Table name validation (M-03) |
| `internal/store/store.go` | Modify | (no changes, interface is stable) |
| `go.mod` | Modify | Add `golang.org/x/term` and `golang.org/x/crypto` |

---

## Phase 1: CRITICAL Security Fixes

### Task 1: Add Argon2id KDF with vault versioning + migrate command (C-01)

**Strategy:** Add a second KDF (Argon2id) alongside existing SHA-256. New vaults use Argon2id (v2). Existing vaults remain on SHA-256 (v1) and continue working. Users opt-in to upgrade via `psst migrate`. The vault stores its KDF version in a `vault_meta` table.

**Key insight:** OS keychain users store a random 32-byte key (base64), so `KeyToBuffer` just decodes it — KDF version is irrelevant for them. Only PSST_PASSWORD users are affected.

**Files:**
- Modify: `internal/crypto/aesgcm.go` — add `KeyToBufferV2` method
- Create: `internal/crypto/kdf.go` — KDF version constants and helpers
- Modify: `internal/store/migrations.go` — add `vault_meta` table
- Modify: `internal/store/store.go` — add `GetMeta`/`SetMeta` to interface
- Modify: `internal/store/sqlite.go` — implement `GetMeta`/`SetMeta`
- Modify: `internal/vault/vault.go` — read KDF version on Unlock, use correct KDF
- Modify: `internal/vault/types.go` — add `KDFVersion` constants
- Create: `internal/cli/migrate.go` — `psst migrate` command
- Modify: `internal/cli/root.go` — register migrate command
- Modify: `go.mod` — add `golang.org/x/crypto`
- Test: `internal/crypto/aesgcm_test.go`, `internal/store/sqlite_test.go`, `internal/vault/vault_test.go`

- [ ] **Step 1: Add dependencies**

Run:
```bash
cd /root/projects/gitlab/tools/psst && go get golang.org/x/crypto && go get golang.org/x/term && go mod tidy
```

- [ ] **Step 2: Create KDF version constants**

Create `internal/crypto/kdf.go`:

```go
package crypto

const (
	KDFVersion1 = 1
	KDFVersion2 = 2

	CurrentKDFVersion = KDFVersion2
)
```

- [ ] **Step 3: Add KeyToBufferV2 with Argon2id to crypto**

Add to `internal/crypto/aesgcm.go` (keep existing `KeyToBuffer` unchanged for v1 compat):

```go
func (a *AESGCM) KeyToBufferV2(key string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	salt := sha256.Sum256([]byte("psst-argon2id-v2-salt"))
	return argon2.IDKey([]byte(key), salt[:], 3, 64*1024, 4, 32), nil
}
```

Add import `"golang.org/x/crypto/argon2"` to `aesgcm.go`.

- [ ] **Step 4: Update Encryptor interface**

In `internal/crypto/crypto.go`:

```go
type Encryptor interface {
	Encrypt(plaintext []byte, key []byte) (ciphertext, iv []byte, err error)
	Decrypt(ciphertext, iv, key []byte) ([]byte, error)
	KeyToBuffer(key string) ([]byte, error)
	KeyToBufferV2(key string) ([]byte, error)
	GenerateKey() ([]byte, error)
}
```

- [ ] **Step 5: Write failing test for Argon2id**

Add to `internal/crypto/aesgcm_test.go`:

```go
func TestKeyToBufferV2_Argon2id(t *testing.T) {
	enc := NewAESGCM()
	key1, err := enc.KeyToBufferV2("mypassword")
	if err != nil {
		t.Fatalf("KeyToBufferV2 failed: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("key length = %d, want 32", len(key1))
	}

	key2, _ := enc.KeyToBufferV2("mypassword")
	if string(key1) != string(key2) {
		t.Fatal("same password should produce same key with Argon2id")
	}

	key3, _ := enc.KeyToBufferV2("otherpassword")
	if string(key1) == string(key3) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestKeyToBufferV2_Base64Passthrough(t *testing.T) {
	enc := NewAESGCM()
	raw := make([]byte, 32)
	raw[0] = 42
	b64 := base64.StdEncoding.EncodeToString(raw)

	result, err := enc.KeyToBufferV2(b64)
	if err != nil {
		t.Fatalf("KeyToBufferV2 failed: %v", err)
	}
	if result[0] != 42 {
		t.Fatalf("first byte = %d, want 42", result[0])
	}
}

func TestKeyToBufferV1_V2_ProduceDifferentKeys(t *testing.T) {
	enc := NewAESGCM()
	v1, _ := enc.KeyToBuffer("mypassword")
	v2, _ := enc.KeyToBufferV2("mypassword")
	if string(v1) == string(v2) {
		t.Fatal("v1 and v2 KDF should produce different keys from same password")
	}
}
```

- [ ] **Step 6: Run crypto tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/crypto/ -v`
Expected: All PASS.

- [ ] **Step 7: Add vault_meta table to store**

In `internal/store/store.go`, add to `SecretStore` interface:

```go
	GetMeta(key string) (string, error)
	SetMeta(key, value string) error
```

In `internal/store/migrations.go`, add to `initSchema` after the index creation:

```go
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS vault_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)
	`)
```

In `internal/store/sqlite.go`, add implementations:

```go
func (s *SQLiteStore) GetMeta(key string) (string, error) {
	var value string
	err := s.queryRow(s.currentTx, "SELECT value FROM vault_meta WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *SQLiteStore) SetMeta(key, value string) error {
	_, err := s.exec(s.currentTx, `INSERT INTO vault_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
```

Note: depends on Task 13 (ARCH-04) being done first for the `currentTx` pattern. If Task 13 is not yet done, use `s.db`/`s.tx` directly.

- [ ] **Step 8: Update vault.Unlock to read KDF version**

In `internal/vault/vault.go`, modify `Unlock`:

```go
func (v *Vault) Unlock() error {
	rawKey, err := v.kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}

	kdfVersion := v.readKDFVersion()
	var key []byte
	switch kdfVersion {
	case crypto.KDFVersion2, 0:
		if kdfVersion == 0 {
			kdfVersion = crypto.CurrentKDFVersion
		}
		key, err = v.enc.(interface{ KeyToBufferV2(string) ([]byte, error) }).KeyToBufferV2(string(rawKey))
	default:
		key, err = v.enc.KeyToBuffer(string(rawKey))
	}
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	v.key = key
	return nil
}
```

Wait, this is getting complex with the keyprovider interface. Let me simplify.

**Better approach:** The KDF version selection happens in `keyring` — specifically in `EnvVarProvider.GetKey` which calls `enc.KeyToBuffer()`. We need to pass the KDF version down.

**Simplest approach:** Move KDF version awareness into the `KeyProvider` construction. When creating the key provider for an existing vault, read the vault_meta first and create the provider with the correct KDF version.

Actually, the cleanest approach:

1. `vault.Unlock()` reads `vault_meta.kdf_version` from store (before key derivation)
2. Passes it to `kp.GetKey()` — but the interface doesn't support that
3. OR: `vault.Unlock()` calls `kp.GetRawKey()` to get the raw password/keychain value, then calls the appropriate KDF itself

Let me redesign:

In `keyring/keyring.go`, add `GetRawKey`:

```go
type KeyProvider interface {
	GetKey(service, account string) ([]byte, error)
	GetRawKey(service, account string) (string, error)
	SetKey(service, account string, key []byte) error
	IsAvailable() bool
	GenerateKey() ([]byte, error)
}
```

`GetRawKey` returns the raw string (password or base64 key) without KDF application.

Then in `vault.Unlock()`:

```go
func (v *Vault) Unlock() error {
	rawKey, err := v.kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}

	kdfVersion := v.readKDFVersion()
	var key []byte
	switch kdfVersion {
	case crypto.KDFVersion2, 0:
		key, err = v.enc.KeyToBufferV2(rawKey)
	default:
		key, err = v.enc.KeyToBuffer(rawKey)
	}
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	v.key = key
	return nil
}

func (v *Vault) readKDFVersion() int {
	val, _ := v.store.GetMeta("kdf_version")
	if val == "" {
		return 1
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 1
	}
	return n
}
```

In `keyring/oskeyring.go`:

```go
func (o *OSKeyring) GetRawKey(service, account string) (string, error) {
	encoded, err := keyring.Get(service, account)
	if err != nil {
		return "", fmt.Errorf("get from keychain: %w", err)
	}
	return encoded, nil
}
```

In `keyring/envvar.go`:

```go
func (e *EnvVarProvider) GetRawKey(service, account string) (string, error) {
	password := os.Getenv("PSST_PASSWORD")
	if password == "" {
		return "", fmt.Errorf("PSST_PASSWORD not set and OS keychain unavailable")
	}
	return password, nil
}
```

The existing `GetKey` method now calls `KeyToBuffer` (v1) by default for backward compat, but `vault.Unlock` will use `GetRawKey` + appropriate KDF.

**In `vault.InitVault`** — new vaults set `kdf_version = 2`:

```go
	if err := s.SetMeta("kdf_version", strconv.Itoa(crypto.CurrentKDFVersion)); err != nil {
		return fmt.Errorf("set vault metadata: %w", err)
	}
```

- [ ] **Step 9: Add psst migrate command**

Create `internal/cli/migrate.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/aatumaykin/psst/internal/crypto"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate vault to latest KDF version",
	Run: func(cmd *cobra.Command, args []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		currentVersion, _ := v.store.GetMeta("kdf_version")
		if currentVersion == fmt.Sprintf("%d", crypto.CurrentKDFVersion) {
			f.Success("Vault is already on latest KDF version")
			return
		}

		if err := v.MigrateKDF(); err != nil {
			exitWithError(fmt.Sprintf("Migration failed: %v", err))
		}

		f.Success(fmt.Sprintf("Vault migrated to KDF version %d", crypto.CurrentKDFVersion))
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
}
```

Add `MigrateKDF` to `vault/vault.go`:

```go
func (v *Vault) MigrateKDF() error {
	if v.key == nil {
		return fmt.Errorf("vault is locked")
	}

	all, err := v.store.GetAllSecrets()
	if err != nil {
		return fmt.Errorf("get secrets: %w", err)
	}

	rawKey, err := v.kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("get raw key: %w", err)
	}

	newKey, err := v.enc.KeyToBufferV2(rawKey)
	if err != nil {
		return fmt.Errorf("derive new key: %w", err)
	}

	return v.store.ExecTx(func() error {
		for _, s := range all {
			plaintext, err := v.enc.Decrypt(s.EncryptedValue, s.IV, v.key)
			if err != nil {
				return fmt.Errorf("decrypt %s: %w", s.Name, err)
			}
			ciphertext, iv, err := v.enc.Encrypt(plaintext, newKey)
			for i := range plaintext {
				plaintext[i] = 0
			}
			if err != nil {
				return fmt.Errorf("encrypt %s: %w", s.Name, err)
			}
			if err := v.store.SetSecret(s.Name, ciphertext, iv, s.Tags); err != nil {
				return fmt.Errorf("update %s: %w", s.Name, err)
			}
		}
		return v.store.SetMeta("kdf_version", fmt.Sprintf("%d", crypto.CurrentKDFVersion))
	})
}
```

- [ ] **Step 10: Run all tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./... -v`
Expected: All PASS. Existing vault tests still pass (v1 compat). New tests for v2 pass.

- [ ] **Step 11: Commit**

```bash
git add internal/crypto/ internal/keyring/ internal/store/ internal/vault/ internal/cli/migrate.go internal/cli/root.go go.mod go.sum
git commit -m "feat(crypto): add Argon2id KDF with vault versioning and migrate command (C-01)

- New vaults use Argon2id (v2) for password-based key derivation
- Existing vaults remain on SHA-256 (v1), fully compatible
- Add 'psst migrate' command to upgrade vault KDF version
- Add vault_meta table for storing KDF version
- Add GetRawKey to KeyProvider interface for KDF-aware key derivation"
```

---

### Task 2: Set restrictive file permissions on vault database (C-02)

**Files:**
- Modify: `internal/store/sqlite.go:17-23`

- [ ] **Step 1: Write failing test**

Add to `internal/store/sqlite_test.go` (after existing tests):

```go
func TestNewSQLite_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	s, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("NewSQLite failed: %v", err)
	}
	s.Close()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		t.Fatalf("file permissions = %o, want no group/other access", perm)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/store/ -v -run TestNewSQLite_FilePermissions`
Expected: FAIL — default umask allows group/other read.

- [ ] **Step 3: Implement the fix**

In `internal/store/sqlite.go`, modify `NewSQLite`:

```go
func NewSQLite(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	os.Chmod(dbPath, 0600)
	return &SQLiteStore{db: db}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/store/ -v -run TestNewSQLite_FilePermissions`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/sqlite.go internal/store/sqlite_test.go
git commit -m "fix(store): set vault database permissions to 0600 (C-02)"
```

---

### Task 3: Fix masking across 4KB buffer boundaries (C-03)

**Files:**
- Modify: `internal/runner/runner.go:67-79`

- [ ] **Step 1: Write failing test**

Add to `internal/runner/runner_test.go`:

```go
func TestStreamWithMasking_BoundarySplit(t *testing.T) {
	secret := "SECRETVALUE"
	chunk1 := "prefix" + secret[:6]
	chunk2 := secret[6:] + "suffix"

	var buf bytes.Buffer
	r, w := io.Pipe()

	go func() {
		w.Write([]byte(chunk1))
		w.Write([]byte(chunk2))
		w.Close()
	}()

	streamWithMasking(r, &buf, []string{secret})

	result := buf.String()
	if strings.Contains(result, secret) {
		t.Fatalf("secret leaked in output: %q", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in output, got: %q", result)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/runner/ -v -run TestStreamWithMasking_BoundarySplit`
Expected: FAIL — secret leaks across boundary.

- [ ] **Step 3: Implement the fix**

Replace `streamWithMasking` in `internal/runner/runner.go`:

```go
func streamWithMasking(src io.Reader, dst io.Writer, secrets []string) {
	maxLen := 0
	for _, s := range secrets {
		if len(s) > maxLen {
			maxLen = len(s)
		}
	}

	overlap := 0
	buf := make([]byte, 4096)
	carry := make([]byte, 0, maxLen)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := append(carry, buf[:n]...)
			masked := MaskSecrets(string(chunk), secrets)

			if overlap > 0 && len(chunk) > overlap {
				writeLen := len(masked) - overlap
				if writeLen > 0 {
					dst.Write([]byte(masked[:writeLen]))
				}
				carry = append(carry[:0], chunk[len(chunk)-overlap:]...)
			} else {
				dst.Write([]byte(masked))
				carry = carry[:0]
			}
		}
		if err != nil {
			if len(carry) > 0 {
				masked := MaskSecrets(string(carry), secrets)
				dst.Write([]byte(masked))
			}
			return
		}
		if maxLen > 0 {
			overlap = maxLen - 1
		}
	}
}
```

- [ ] **Step 4: Run all runner tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/runner/ -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "fix(runner): handle secrets split across buffer boundaries (C-03)"
```

---

## Phase 2: HIGH Security Fixes

### Task 4: Sort secrets by descending length before masking (H-01)

**Files:**
- Modify: `internal/runner/mask.go:5-11`

- [ ] **Step 1: Write failing test**

Add to `internal/runner/runner_test.go`:

```go
func TestMaskSecrets_SubstringOrder(t *testing.T) {
	secrets := []string{"sk-abc", "sk-abc123def"}
	text := "key=sk-abc123def and short=sk-abc"

	result := MaskSecrets(text, secrets)
	if strings.Contains(result, "sk-abc123def") {
		t.Fatal("longer secret should be masked")
	}
	if strings.Contains(result, "sk-abc") {
		t.Fatal("shorter secret should be masked")
	}
	count := strings.Count(result, "[REDACTED]")
	if count != 2 {
		t.Fatalf("expected 2 [REDACTED] occurrences, got %d", count)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/runner/ -v -run TestMaskSecrets_SubstringOrder`
Expected: May fail intermittently due to map iteration order randomization.

- [ ] **Step 3: Implement the fix**

Replace `internal/runner/mask.go`:

```go
package runner

import (
	"sort"
	"strings"
)

func MaskSecrets(text string, secrets []string) string {
	sorted := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if len(s) > 0 {
			sorted = append(sorted, s)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})
	for _, s := range sorted {
		text = strings.ReplaceAll(text, s, "[REDACTED]")
	}
	return text
}
```

- [ ] **Step 4: Run all runner tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/runner/ -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/runner/mask.go internal/runner/runner_test.go
git commit -m "fix(runner): sort secrets by descending length before masking (H-01)"
```

---

### Task 5: Fix `$NAME` expansion to be word-boundary aware (H-02)

**Files:**
- Modify: `internal/runner/expand.go:8-22`

- [ ] **Step 1: Write failing test**

Add to `internal/runner/runner_test.go`:

```go
func TestExpandEnvVars_WordBoundary(t *testing.T) {
	env := map[string]string{
		"API": "api-value",
	}
	got := ExpandEnvVars("$API_KEY", env)
	if got == "api-value_KEY" {
		t.Fatalf("$API should not partially expand inside $API_KEY, got: %q", got)
	}
	if got != "$API_KEY" {
		t.Fatalf("expected $API_KEY to remain unexpanded, got: %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/runner/ -v -run TestExpandEnvVars_WordBoundary`
Expected: FAIL — `$API` partially expands inside `$API_KEY`.

- [ ] **Step 3: Implement the fix**

Replace `internal/runner/expand.go`:

```go
package runner

import (
	"regexp"
	"slices"
	"strings"
)

func ExpandEnvVars(arg string, env map[string]string) string {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })

	result := arg
	for _, name := range names {
		value := env[name]
		result = strings.ReplaceAll(result, "${"+name+"}", value)

		pattern := regexp.MustCompile(`\$` + regexp.QuoteMeta(name) + `(?![A-Za-z0-9_])`)
		result = pattern.ReplaceAllString(result, value)
	}

	return result
}
```

- [ ] **Step 4: Run all runner tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/runner/ -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/runner/expand.go internal/runner/runner_test.go
git commit -m "fix(runner): word-boundary aware $NAME expansion (H-02)"
```

---

### Task 6: Use term.ReadPassword for interactive secret input (H-03)

**Files:**
- Modify: `internal/cli/set.go:32-42`

- [ ] **Step 1: Implement the fix**

In `internal/cli/set.go`, replace the interactive input block:

Replace imports:
```go
import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)
```

Replace the `else` block in the `Run` function (lines 37-42):
```go
		} else {
			fmt.Printf("Enter value for %s: ", name)
			bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				exitWithError(fmt.Sprintf("Failed to read password: %v", err))
			}
			value = strings.TrimSpace(string(bytes))
		}
```

Remove the `"bufio"` import — it is no longer used.

- [ ] **Step 2: Build and verify compilation**

Run: `cd /root/projects/gitlab/tools/psst && go build ./...`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/set.go
git commit -m "fix(cli): use term.ReadPassword to hide secret input (H-03)"
```

---

### Task 7: Set restrictive permissions on export file (H-04)

**Files:**
- Modify: `internal/cli/export.go:28-33`

- [ ] **Step 1: Implement the fix**

In `internal/cli/export.go`, replace line 29:

```go
		file, err := os.OpenFile(envFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
```

- [ ] **Step 2: Build and verify**

Run: `cd /root/projects/gitlab/tools/psst && go build ./...`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/export.go
git commit -m "fix(cli): create export file with 0600 permissions (H-04)"
```

---

### Task 8: Best-effort memory zeroing for keys and plaintext (H-05)

**Files:**
- Modify: `internal/vault/vault.go`

- [ ] **Step 1: Write failing test**

Add to `internal/vault/vault_test.go`:

```go
func TestVaultClose_ZerosKey(t *testing.T) {
	v := setupTestVault(t)
	v.SetSecret("TEST", "secretdata", nil)

	key := v.key
	for _, b := range key {
		if b != 0 {
			return
		}
	}
	t.Fatal("key should not be all zeros before Close")
}
```

- [ ] **Step 2: Implement the fix**

In `internal/vault/vault.go`, modify `Close()` and add zeroing in `GetSecret` / `GetAllSecrets`:

Replace `Close()`:
```go
func (v *Vault) Close() error {
	for i := range v.key {
		v.key[i] = 0
	}
	v.key = nil
	return v.store.Close()
}
```

In `GetSecret`, add zeroing after use (after line 139):
```go
	plaintext, err := v.enc.Decrypt(stored.EncryptedValue, stored.IV, v.key)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()

	return &Secret{
		Name:      stored.Name,
		Value:     string(plaintext),
		Tags:      stored.Tags,
		CreatedAt: stored.CreatedAt,
		UpdatedAt: stored.UpdatedAt,
	}, nil
```

In `GetAllSecrets`, add zeroing in the loop (around line 277):
```go
	for _, s := range all {
		plaintext, err := v.enc.Decrypt(s.EncryptedValue, s.IV, v.key)
		if err != nil {
			for _, prev := range result {
				_ = prev
			}
			return nil, fmt.Errorf("decrypt %s: %w", s.Name, err)
		}
		result[s.Name] = string(plaintext)
	}
```

Note: Since `string(plaintext)` copies the data and we can't zero the string, the `defer` zeroing of `plaintext` []byte is best-effort.

- [ ] **Step 3: Run tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/vault/ -v`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "fix(vault): zero encryption key and plaintext in memory (H-05)"
```

---

## Phase 3: Architecture Fixes

### Task 9: Break keyring → crypto dependency (ARCH-01)

**Files:**
- Modify: `internal/keyring/keyring.go`
- Modify: `internal/keyring/oskeyring.go`
- Modify: `internal/keyring/envvar.go`
- Modify: `internal/cli/root.go:82-86`

- [ ] **Step 1: Define KeyDeriver interface in keyring**

Replace `internal/keyring/keyring.go`:

```go
package keyring

import (
	"os"
)

type KeyDeriver interface {
	KeyToBuffer(key string) ([]byte, error)
	GenerateKey() ([]byte, error)
}

type KeyProvider interface {
	GetKey(service, account string) ([]byte, error)
	SetKey(service, account string, key []byte) error
	IsAvailable() bool
	GenerateKey() ([]byte, error)
}

func NewProvider(deriver KeyDeriver) KeyProvider {
	os := &OSKeyring{deriver: deriver}
	if os.IsAvailable() {
		return os
	}
	return &EnvVarProvider{deriver: deriver}
}

func IsKeychainAvailable() bool {
	return (&OSKeyring{}).IsAvailable()
}

func IsEnvPasswordSet() bool {
	return os.Getenv("PSST_PASSWORD") != ""
}
```

- [ ] **Step 2: Update OSKeyring**

Replace `internal/keyring/oskeyring.go`:

```go
package keyring

import (
	"encoding/base64"
	"fmt"

	keyring "github.com/zalando/go-keyring"
)

type OSKeyring struct {
	deriver KeyDeriver
}

func (o *OSKeyring) GetKey(service, account string) ([]byte, error) {
	encoded, err := keyring.Get(service, account)
	if err != nil {
		return nil, fmt.Errorf("get from keychain: %w", err)
	}
	if o.deriver != nil {
		return o.deriver.KeyToBuffer(encoded)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	return decoded, nil
}

func (o *OSKeyring) SetKey(service, account string, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return keyring.Set(service, account, encoded)
}

func (o *OSKeyring) IsAvailable() bool {
	const testSvc = "psst-avail-check"
	const testAcc = "test"
	const testVal = "psst-availability-probe"
	if err := keyring.Set(testSvc, testAcc, testVal); err != nil {
		return false
	}
	got, err := keyring.Get(testSvc, testAcc)
	keyring.Delete(testSvc, testAcc)
	return err == nil && got == testVal
}

func (o *OSKeyring) GenerateKey() ([]byte, error) {
	if o.deriver != nil {
		return o.deriver.GenerateKey()
	}
	return nil, fmt.Errorf("no key deriver available")
}
```

- [ ] **Step 3: Update EnvVarProvider**

Replace `internal/keyring/envvar.go`:

```go
package keyring

import (
	"fmt"
	"os"
)

type EnvVarProvider struct {
	deriver KeyDeriver
}

func (e *EnvVarProvider) GetKey(service, account string) ([]byte, error) {
	password := os.Getenv("PSST_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("PSST_PASSWORD not set and OS keychain unavailable")
	}
	return e.deriver.KeyToBuffer(password)
}

func (e *EnvVarProvider) SetKey(service, account string, key []byte) error {
	return nil
}

func (e *EnvVarProvider) IsAvailable() bool {
	return os.Getenv("PSST_PASSWORD") != ""
}

func (e *EnvVarProvider) GenerateKey() ([]byte, error) {
	return e.deriver.GenerateKey()
}
```

- [ ] **Step 4: Update CLI wiring**

In `internal/cli/root.go`, update `createDependencies`:

```go
func createDependencies() (crypto.Encryptor, keyring.KeyProvider) {
	enc := crypto.NewAESGCM()
	kp := keyring.NewProvider(enc)
	return enc, kp
}
```

This stays the same — but now `keyring.NewProvider` accepts `KeyDeriver` interface instead of `*crypto.AESGCM`.

- [ ] **Step 5: Build and run all tests**

Run: `cd /root/projects/gitlab/tools/psst && go build ./... && go test ./... -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/keyring/ internal/cli/root.go
git commit -m "refactor(keyring): accept KeyDeriver interface instead of *crypto.AESGCM (ARCH-01)"
```

---

### Task 10: Wrap Rollback in transaction + fix AddHistory error (ARCH-03, QUAL-02)

**Files:**
- Modify: `internal/vault/vault.go:173-206`

- [ ] **Step 1: Implement the fix**

Replace the `Rollback` method in `internal/vault/vault.go`:

```go
func (v *Vault) Rollback(name string, version int) error {
	if v.key == nil {
		return fmt.Errorf("vault is locked")
	}

	current, err := v.store.GetSecret(name)
	if err != nil {
		return err
	}
	if current == nil {
		return fmt.Errorf("secret %q not found", name)
	}

	history, err := v.store.GetHistory(name)
	if err != nil {
		return err
	}

	var target *store.HistoryEntry
	for i := range history {
		if history[i].Version == version {
			target = &history[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("version %d not found", version)
	}

	return v.store.ExecTx(func() error {
		newVersion := len(history) + 1
		if err := v.store.AddHistory(name, newVersion, current.EncryptedValue, current.IV, current.Tags); err != nil {
			return fmt.Errorf("archive history: %w", err)
		}
		return v.store.SetSecret(name, target.EncryptedValue, target.IV, target.Tags)
	})
}
```

- [ ] **Step 2: Run vault tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/vault/ -v`
Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/vault/vault.go
git commit -m "fix(vault): wrap Rollback in transaction, check AddHistory error (ARCH-03, QUAL-02)"
```

---

### Task 11: Propagate subprocess exit code in exec pattern (ARCH-05)

**Files:**
- Modify: `internal/cli/exec.go:39-41`

- [ ] **Step 1: Implement the fix**

Replace `internal/cli/exec.go` entirely:

```go
package cli

import (
	"fmt"
	"os"

	"github.com/aatumaykin/psst/internal/runner"
)

func handleExecPatternDirect(secretNames []string, commandArgs []string, jsonOut, quiet, global bool, env string, tags []string, noMask bool) {
	v, err := getUnlockedVault(jsonOut, quiet, global, env)
	if err != nil {
		exitWithError(err.Error())
	}
	defer v.Close()

	secrets := make(map[string]string)

	if len(tags) > 0 {
		names, err := v.GetSecretNamesByTags(tags)
		if err != nil {
			exitWithError(err.Error())
		}
		secretNames = append(secretNames, names...)
	}

	for _, name := range secretNames {
		sec, err := v.GetSecret(name)
		if err != nil {
			exitWithError(err.Error())
		}
		if sec != nil {
			secrets[name] = sec.Value
		}
	}

	r := getRunner()
	maskOutput := !noMask
	code, err := r.Exec(secrets, commandArgs[0], commandArgs[1:], runner.ExecOptions{MaskOutput: maskOutput})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Command failed: %v\n", err)
	}
	os.Exit(code)
}
```

- [ ] **Step 2: Build and verify**

Run: `cd /root/projects/gitlab/tools/psst && go build ./...`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/exec.go
git commit -m "fix(cli): propagate subprocess exit code in exec pattern (ARCH-05)"
```

---

### Task 12: Remove SecretMeta type alias from vault (ARCH-02)

**Files:**
- Modify: `internal/vault/types.go`
- Modify: `internal/vault/vault.go` (ListSecrets return type)
- Modify: `internal/output/output.go` (import store directly)

- [ ] **Step 1: Define own SecretMeta in vault**

Replace `internal/vault/types.go`:

```go
package vault

import (
	"time"

	"github.com/aatumaykin/psst/internal/store"
)

type Secret struct {
	Name      string
	Value     string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SecretMeta struct {
	Name      string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SecretHistoryEntry struct {
	Version    int
	Tags       []string
	ArchivedAt time.Time
}

type InitOptions struct {
	Global       bool
	Env          string
	SkipKeychain bool
	Key          string
}

func metaFromStore(m store.SecretMeta) SecretMeta {
	return SecretMeta{
		Name:      m.Name,
		Tags:      m.Tags,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}
```

- [ ] **Step 2: Update vault.ListSecrets to return own type**

In `internal/vault/vault.go`, update `ListSecrets`:

```go
func (v *Vault) ListSecrets() ([]SecretMeta, error) {
	storeMetas, err := v.store.ListSecrets()
	if err != nil {
		return nil, err
	}
	result := make([]SecretMeta, len(storeMetas))
	for i, m := range storeMetas {
		result[i] = metaFromStore(m)
	}
	return result, nil
}
```

Update `GetSecretsByTags` similarly — the returned `SecretMeta` is now `vault.SecretMeta`, and the internal call returns `store.SecretMeta`, so map it.

- [ ] **Step 3: Update output to import vault.SecretMeta**

`output/output.go` already imports `vault`. The `SecretList` method signature uses `[]vault.SecretMeta` which now refers to the vault-own type. No change needed in output if the fields match (they do).

- [ ] **Step 4: Build and test**

Run: `cd /root/projects/gitlab/tools/psst && go build ./... && go test ./... -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/types.go internal/vault/vault.go internal/output/output.go
git commit -m "refactor(vault): define own SecretMeta instead of type alias (ARCH-02)"
```

---

### Task 13: Fix ExecTx data race (ARCH-04)

**Files:**
- Modify: `internal/store/sqlite.go:25-44, 195-209`

- [ ] **Step 1: Implement the fix — pass *sql.Tx through closure**

Add a transaction-aware query helper pattern. Replace `exec`, `query`, `queryRow` and `ExecTx`:

```go
type txCtx struct {
	tx *sql.Tx
}

func (s *SQLiteStore) exec(ctx *txCtx, query string, args ...any) (sql.Result, error) {
	if ctx != nil && ctx.tx != nil {
		return ctx.tx.Exec(query, args...)
	}
	return s.db.Exec(query, args...)
}

func (s *SQLiteStore) query(ctx *txCtx, query string, args ...any) (*sql.Rows, error) {
	if ctx != nil && ctx.tx != nil {
		return ctx.tx.Query(query, args...)
	}
	return s.db.Query(query, args...)
}

func (s *SQLiteStore) queryRow(ctx *txCtx, query string, args ...any) *sql.Row {
	if ctx != nil && ctx.tx != nil {
		return ctx.tx.QueryRow(query, args...)
	}
	return s.db.QueryRow(query, args...)
}

func (s *SQLiteStore) ExecTx(fn func() error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	s.currentTx = &txCtx{tx: tx}
	defer func() { s.currentTx = nil }()

	if err := fn(); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
```

Then rename the struct field from `tx *sql.Tx` to `currentTx *txCtx` and update all callers of `s.exec`/`s.query`/`s.queryRow` to pass `s.currentTx`.

This is a larger refactor. Each method in `sqlite.go` needs updating:
- `GetSecret`: `s.queryRow(s.currentTx, ...)`
- `GetAllSecrets`: `s.query(s.currentTx, ...)`
- `SetSecret`: `s.exec(s.currentTx, ...)`
- `DeleteSecret`: `s.exec(s.currentTx, ...)`
- etc.

- [ ] **Step 2: Run all tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./... -v -race`
Expected: All tests PASS with no race detector warnings.

- [ ] **Step 3: Commit**

```bash
git add internal/store/sqlite.go
git commit -m "fix(store): eliminate ExecTx data race with txCtx (ARCH-04)"
```

---

## Phase 4: Code Quality Fixes

### Task 14: Extract store scan helper for tags/time parsing (QUAL-01, REFACT-02)

**Files:**
- Modify: `internal/store/sqlite.go`

- [ ] **Step 1: Add helper function**

Add to `internal/store/sqlite.go`:

```go
func scanTagsAndTimes(tagsJSON string, createdAt, updatedAt string) (tags []string, created, updated time.Time, err error) {
	if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("parse tags: %w", err)
	}
	created, err = time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("parse created_at: %w", err)
	}
	updated, err = time.Parse("2006-01-02 15:04:05", updatedAt)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return tags, created, updated, nil
}
```

- [ ] **Step 2: Replace all 4 occurrences**

Replace the 3-line pattern in `GetSecret`, `GetAllSecrets`, `ListSecrets`, and `GetHistory` with calls to `scanTagsAndTimes`. Example for `GetSecret`:

```go
	sec.Tags, sec.CreatedAt, sec.UpdatedAt, err = scanTagsAndTimes(tagsJSON, createdAt, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse secret metadata: %w", err)
	}
```

- [ ] **Step 3: Run tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/store/ -v`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/store/sqlite.go
git commit -m "refactor(store): extract scanTagsAndTimes helper, handle parse errors (QUAL-01, REFACT-02)"
```

---

### Task 15: Fix nil dereference in history command (QUAL-06, L-03)

**Files:**
- Modify: `internal/cli/history.go:36`
- Modify: `internal/output/output.go:83`

- [ ] **Step 1: Change HistoryEntries signature**

In `internal/output/output.go`, change `HistoryEntries`:

```go
func (f *Formatter) HistoryEntries(name string, entries []vault.SecretHistoryEntry) {
```

Remove the `current *vault.Secret` parameter. Remove the `(active)` marker since we no longer have the current secret.

- [ ] **Step 2: Update history.go caller**

In `internal/cli/history.go`, remove the `GetSecret` call:

```go
		entries, err := v.GetHistory(name)
		if err != nil {
			exitWithError(err.Error())
		}

		if len(entries) == 0 {
			if !quiet {
				fmt.Printf("No history for %s\n", name)
			}
			return
		}

		f.HistoryEntries(name, entries)
```

- [ ] **Step 3: Build and test**

Run: `cd /root/projects/gitlab/tools/psst && go build ./... && go test ./... -v`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/history.go internal/output/output.go
git commit -m "fix(cli): remove unnecessary GetSecret in history, fix nil dereference (QUAL-06, L-03)"
```

---

### Task 16: Fix remaining quality issues (QUAL-04, QUAL-08, L-01, L-08)

**Files:**
- Modify: `internal/output/output.go:157-161`
- Modify: `internal/cli/init.go:44-48`
- Modify: `internal/cli/args.go:42`
- Modify: `internal/cli/get.go`

- [ ] **Step 1: Fix printJSON error handling (QUAL-04)**

In `internal/output/output.go`:

```go
func (f *Formatter) printJSON(data any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encoding error: %v\n", err)
	}
}
```

- [ ] **Step 2: Fix init.go to use Formatter (QUAL-08)**

In `internal/cli/init.go`, replace lines 44-48:

```go
		if !keychainAvailable {
			f.Warning("Using PSST_PASSWORD (OS keychain unavailable)")
			f.Bullet("Set PSST_PASSWORD before each use:")
			f.Bullet(`export PSST_PASSWORD="your-password"`)
		}
```

- [ ] **Step 3: Fix args.go --env skip logic (L-01)**

In `internal/cli/args.go`, replace `filterSecretNames`:

```go
func filterSecretNames(args []string, jsonOut, quiet, global bool, env string, tags []string) []string {
	skip := map[string]bool{"--json": true, "--quiet": true, "-q": true, "--global": true, "-g": true, "--no-mask": true, "--env": true, "--tag": true}
	envValueIdx := -1
	for i, a := range args {
		if a == "--env" && i+1 < len(args) {
			envValueIdx = i + 1
		}
		if a == "--tag" && i+1 < len(args) {
			envValueIdx = i + 1
		}
	}
	var names []string
	for i, a := range args {
		if skip[a] || i == envValueIdx {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	return names
}
```

Wait, that only tracks the last `--env`/`--tag` value. Need to track all. Better approach:

```go
func filterSecretNames(args []string, jsonOut, quiet, global bool, env string, tags []string) []string {
	skip := map[string]bool{"--json": true, "--quiet": true, "-q": true, "--global": true, "-g": true, "--no-mask": true}
	valueArgs := map[int]bool{}
	for i, a := range args {
		if (a == "--env" || a == "--tag") && i+1 < len(args) {
			valueArgs[i] = true
			valueArgs[i+1] = true
		}
	}
	var names []string
	for i, a := range args {
		if skip[a] || valueArgs[i] {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	return names
}
```

- [ ] **Step 4: Add name validation in get command (L-08)**

In `internal/cli/get.go`, add validation after getting the name:

```go
		name := args[0]
		if !validName.MatchString(name) {
			exitWithError(fmt.Sprintf("Invalid secret name %q. Must match [A-Z][A-Z0-9_]*", name))
		}
```

Add import `"regexp"` is not needed — `validName` is defined in `set.go` in the same package.

- [ ] **Step 5: Build and test**

Run: `cd /root/projects/gitlab/tools/psst && go build ./... && go test ./... -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/output/output.go internal/cli/init.go internal/cli/args.go internal/cli/get.go
git commit -m "fix: printJSON error handling, init formatter, args parsing, get validation (QUAL-04, QUAL-08, L-01, L-08)"
```

---

### Task 17: Fix migrations.go table name validation (M-03)

**Files:**
- Modify: `internal/store/migrations.go:44`

- [ ] **Step 1: Add validation**

In `internal/store/migrations.go`, add at top of `migrateAddTagsColumn`:

```go
func migrateAddTagsColumn(db *sql.DB, table string) error {
	allowed := map[string]bool{"secrets": true, "secrets_history": true}
	if !allowed[table] {
		return fmt.Errorf("unknown table: %s", table)
	}
	// ... rest unchanged
```

- [ ] **Step 2: Build and test**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/store/ -v`
Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/store/migrations.go
git commit -m "fix(store): validate table name in migration (M-03)"
```

---

### Task 18: Refactor parseEnvFromReader to accept io.Reader (REFACT-05)

**Files:**
- Modify: `internal/cli/import.go:72`

- [ ] **Step 1: Change signature**

In `internal/cli/import.go`:

```go
func parseEnvFromReader(r io.Reader) (map[string]string, error) {
	entries := make(map[string]string)
	scanner := bufio.NewScanner(r)
```

Add `"io"` to imports. Update the caller at line 33 and 44 to pass `os.Stdin` and `file` (both are `io.Reader` already, so no other changes needed).

- [ ] **Step 2: Build and test**

Run: `cd /root/projects/gitlab/tools/psst && go build ./...`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/import.go
git commit -m "refactor(cli): parseEnvFromReader accepts io.Reader (REFACT-05)"
```

---

## Phase 5: Test Coverage

### Task 19: Add missing tests for runner package (P0)

**Files:**
- Modify: `internal/runner/runner_test.go`

- [ ] **Step 1: Add tests for Exec, exitCode, ExpandEnvVars edge cases**

```go
func TestExitCode(t *testing.T) {
	if code := exitCode(nil); code != 0 {
		t.Fatalf("exitCode(nil) = %d, want 0", code)
	}
}

func TestMaskSecrets_MultipleSecrets(t *testing.T) {
	secrets := []string{"alpha", "beta"}
	text := "alpha and beta"
	result := MaskSecrets(text, secrets)
	if strings.Contains(result, "alpha") || strings.Contains(result, "beta") {
		t.Fatalf("secrets leaked: %q", result)
	}
	if strings.Count(result, "[REDACTED]") != 2 {
		t.Fatalf("expected 2 [REDACTED], got: %q", result)
	}
}

func TestExpandEnvVars_EmptyEnv(t *testing.T) {
	got := ExpandEnvVars("$FOO", map[string]string{})
	if got != "$FOO" {
		t.Fatalf("expected $FOO unchanged, got %q", got)
	}
}

func TestExpandEnvVars_LongerNameFirst(t *testing.T) {
	env := map[string]string{
		"A":   "short",
		"ABC": "long",
	}
	got := ExpandEnvVars("$ABC", env)
	if got != "long" {
		t.Fatalf("expected 'long', got %q", got)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/runner/ -v`
Expected: All PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/runner/runner_test.go
git commit -m "test(runner): add tests for exitCode, masking, expansion edge cases"
```

---

### Task 20: Add missing tests for vault package (P1)

**Files:**
- Modify: `internal/vault/vault_test.go`

- [ ] **Step 1: Add tests for locked vault, FindVaultPath, Rollback errors**

```go
func TestVault_LockedOperations(t *testing.T) {
	enc := crypto.NewAESGCM()
	kp := &testKeyProvider{key: nil}
	s, _ := store.NewSQLite(filepath.Join(t.TempDir(), "test.db"))
	defer s.Close()
	s.InitSchema()

	v := New(enc, kp, s)

	if err := v.SetSecret("A", "val", nil); err == nil {
		t.Fatal("SetSecret on locked vault should fail")
	}
	if _, err := v.GetSecret("A"); err == nil {
		t.Fatal("GetSecret on locked vault should fail")
	}
	if _, err := v.GetAllSecrets(); err == nil {
		t.Fatal("GetAllSecrets on locked vault should fail")
	}
}

func TestFindVaultPath(t *testing.T) {
	tests := []struct {
		name   string
		global bool
		env    string
		want   string
	}{
		{"default", false, "", ".psst/vault.db"},
		{"global", true, "", ".psst/vault.db"},
		{"env", false, "prod", ".psst/envs/prod/vault.db"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindVaultPath(tt.global, tt.env)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(got, tt.want) {
				t.Fatalf("got %q, want suffix %q", got, tt.want)
			}
		})
	}
}

func TestRollback_SecretNotFound(t *testing.T) {
	v := setupTestVault(t)
	err := v.Rollback("NONEXISTENT", 1)
	if err == nil {
		t.Fatal("rollback nonexistent secret should fail")
	}
}

func TestRollback_VersionNotFound(t *testing.T) {
	v := setupTestVault(t)
	v.SetSecret("TEST", "val", nil)
	err := v.Rollback("TEST", 999)
	if err == nil {
		t.Fatal("rollback nonexistent version should fail")
	}
}
```

- [ ] **Step 2: Run tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/vault/ -v`
Expected: All PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/vault/vault_test.go
git commit -m "test(vault): add tests for locked vault, FindVaultPath, Rollback errors"
```

---

### Task 21: Add missing tests for store package (P1)

**Files:**
- Modify: `internal/store/sqlite_test.go`

- [ ] **Step 1: Add tests for GetAllSecrets, ExecTx, SetSecret upsert**

```go
func TestGetAllSecrets(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	s.SetSecret("A", []byte("encA"), []byte("ivA"), []string{"tag1"})
	s.SetSecret("B", []byte("encB"), []byte("ivB"), nil)

	all, err := s.GetAllSecrets()
	if err != nil {
		t.Fatalf("GetAllSecrets failed: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("len = %d, want 2", len(all))
	}
}

func TestExecTx_Commit(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	err := s.ExecTx(func() error {
		return s.SetSecret("TX", []byte("enc"), []byte("iv"), nil)
	})
	if err != nil {
		t.Fatalf("ExecTx failed: %v", err)
	}

	sec, _ := s.GetSecret("TX")
	if sec == nil {
		t.Fatal("secret should exist after commit")
	}
}

func TestExecTx_Rollback(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	err := s.ExecTx(func() error {
		s.SetSecret("TX", []byte("enc"), []byte("iv"), nil)
		return fmt.Errorf("intentional error")
	})
	if err == nil {
		t.Fatal("ExecTx should return error")
	}

	sec, _ := s.GetSecret("TX")
	if sec != nil {
		t.Fatal("secret should not exist after rollback")
	}
}

func TestSetSecret_Upsert(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	s.SetSecret("K", []byte("enc1"), []byte("iv1"), nil)
	s.SetSecret("K", []byte("enc2"), []byte("iv2"), []string{"t"})

	sec, _ := s.GetSecret("K")
	if sec == nil {
		t.Fatal("secret should exist")
	}
	if string(sec.EncryptedValue) != "enc2" {
		t.Fatalf("value = %q, want %q", sec.EncryptedValue, "enc2")
	}
}
```

- [ ] **Step 2: Run tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./internal/store/ -v`
Expected: All PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/store/sqlite_test.go
git commit -m "test(store): add tests for GetAllSecrets, ExecTx, upsert"
```

---

## Phase 6: Final Verification

### Task 22: Run full test suite and build

- [ ] **Step 1: Run all tests with race detector**

Run: `cd /root/projects/gitlab/tools/psst && go test ./... -v -race`
Expected: All PASS, no race conditions.

- [ ] **Step 2: Build binary**

Run: `cd /root/projects/gitlab/tools/psst && make build`
Expected: Binary built successfully.

- [ ] **Step 3: Run integration tests**

Run: `cd /root/projects/gitlab/tools/psst && go test ./tests/ -v`
Expected: All PASS.

- [ ] **Step 4: Verify no import cycle**

Run: `cd /root/projects/gitlab/tools/psst && go vet ./...`
Expected: No warnings.

- [ ] **Step 5: Final commit (if any remaining changes)**

```bash
git add -A
git commit -m "chore: final verification after security audit fixes"
```

# Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all security, architecture, and robustness findings from the comprehensive audit of psst.

**Architecture:** Bottom-up approach in 6 phases: security P0 fixes → vault.go split → vault.Open() factory → CLI refactoring → robustness improvements → tests. Each phase produces a compilable, test-passing state.

**Tech Stack:** Go 1.26, Cobra CLI, SQLite (modernc.org/sqlite), AES-256-GCM + Argon2id, OS keychain (go-keyring).

---

## File Structure

**New files:**
- `internal/vault/path.go` — FindVaultPath + env name validation
- `internal/vault/init.go` — InitVault
- `internal/vault/unlock.go` — Unlock, failUnlock, readKDFVersion, checkLockout, deriveKey, verifyKey, resetFailedAttempts
- `internal/vault/secrets.go` — SetSecret, GetSecret, ListSecrets, DeleteSecret, GetAllSecrets, ErrSecretNotFound
- `internal/vault/history.go` — GetHistory, Rollback, maxVersion
- `internal/vault/tags.go` — AddTag, RemoveTag, GetSecretsByTags, GetSecretNamesByTags, GetSecretsByTagValues
- `internal/vault/migrate.go` — MigrateKDF
- `internal/vault/validation.go` — ValidateSecretName, ValidateTags, exported regex + constants
- `internal/vault/interface.go` — VaultInterface for CLI testability

**Modified files:**
- `internal/vault/vault.go` — reduced to struct + New + Close + requireUnlock + Open
- `internal/vault/types.go` — add InitOptions (already exists, no change)
- `internal/cli/root.go` — remove store/crypto/keyring imports, add withVault, exit constants
- `internal/cli/exec.go` — ExecConfig struct, use VaultInterface + ValidateSecretName
- `internal/cli/set.go` — use vault.ValidateSecretName, withVault
- `internal/cli/get.go` — use vault.ValidateSecretName, withVault
- `internal/cli/rm.go` — use vault.ValidateSecretName, withVault
- `internal/cli/history.go` — use vault.ValidateSecretName, withVault
- `internal/cli/rollback.go` — use vault.ValidateSecretName, withVault
- `internal/cli/tag.go` — use vault.ValidateSecretName, withVault
- `internal/cli/import.go` — use vault.ValidateSecretName, withVault
- `internal/cli/run.go` — use withVault
- `internal/cli/export.go` — use withVault
- `internal/cli/scan.go` — use withVault
- `internal/cli/migrate.go` — use withVault
- `internal/cli/init.go` — use vault.Open in InitVault path
- `internal/cli/args.go` — remove dead params from filterSecretNames
- `internal/cli/update.go` — use Formatter consistently
- `internal/crypto/aesgcm.go` — add runtime.KeepAlive to ZeroBytes
- `internal/store/sqlite.go` — PRAGMA integrity_check on open, ExecTx doc
- `internal/keyring/oskeyring.go` — PSST_PASSWORD fallback

---

## Phase 1: Security P0

### Task 1: Path traversal in --env (S-1)

**Files:**
- Modify: `internal/vault/vault.go:56-71`
- Test: `internal/vault/vault_test.go`

- [ ] **Step 1: Add env name validation test**

Add to `internal/vault/vault_test.go`:

```go
func TestFindVaultPath_RejectsTraversal(t *testing.T) {
	for _, env := range []string{"../etc", "..", "a/b", "a..b"} {
		t.Run(env, func(t *testing.T) {
			_, err := FindVaultPath(false, env)
			if err == nil {
				t.Fatalf("FindVaultPath(%q) should reject", env)
			}
		})
	}
}

func TestFindVaultPath_AcceptsValidEnv(t *testing.T) {
	for _, env := range []string{"prod", "staging-1", "test_env", "v2"} {
		t.Run(env, func(t *testing.T) {
			_, err := FindVaultPath(false, env)
			if err != nil {
				t.Fatalf("FindVaultPath(%q) should accept: %v", env, err)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run TestFindVaultPath_Rejects -v`
Expected: FAIL — FindVaultPath does not validate env names

- [ ] **Step 3: Add envNameRegex and validation to FindVaultPath**

In `internal/vault/vault.go`, add after the `secretNameRegex` var (line 48):

```go
var envNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
```

Change `FindVaultPath` to validate env:

```go
func FindVaultPath(global bool, env string) (string, error) {
	if env != "" && !envNameRegex.MatchString(env) {
		return "", fmt.Errorf("invalid env name %q: must match %s", env, envNameRegex.String())
	}

	baseDir := ".psst"
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home dir: %w", err)
		}
		baseDir = filepath.Join(home, ".psst")
	}

	if env != "" {
		baseDir = filepath.Join(baseDir, "envs", env)
	}

	return filepath.Join(baseDir, "vault.db"), nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/vault/ -run TestFindVaultPath -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "fix: validate env name to prevent path traversal"
```

---

### Task 2: TOCTOU in Unlock — verify key before storing (S-2)

**Files:**
- Modify: `internal/vault/vault.go:146-222`

- [ ] **Step 1: Write failing test for concurrent unlock safety**

Add to `internal/vault/vault_test.go`:

```go
func TestUnlock_DoesNotExposeUnverifiedKey(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	enc := crypto.NewAESGCM()

	rightKey, err := enc.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	kp := &testKeyProvider{enc: enc, key: rightKey}

	ctx := context.Background()
	if err = InitVault(ctx, dbPath, enc, kp, InitOptions{SkipKeychain: true}); err != nil {
		t.Fatal(err)
	}

	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	wrongKey, _ := enc.GenerateKey()
	wrongKey[0] ^= 0xFF
	wrongKp := &testKeyProvider{enc: enc, key: wrongKey}

	v := New(enc, wrongKp, s)
	defer v.Close()

	unlockErr := v.Unlock(ctx)
	if unlockErr == nil {
		t.Fatal("wrong key should fail unlock")
	}

	if v.key != nil {
		t.Fatal("v.key must be nil after failed unlock — unverified key was exposed")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run TestUnlock_DoesNotExposeUnverifiedKey -v`
Expected: FAIL — `v.key` is set before verification

- [ ] **Step 3: Fix Unlock to use local key variable**

Replace the `Unlock` method in `internal/vault/vault.go` (lines 147-222). The key change: store derived key in local `key` variable, only assign `v.key = key` after successful verification:

```go
func (v *Vault) Unlock(ctx context.Context) error {
	if lockedUntil, _ := v.store.GetMeta(ctx, metaUnlockLockedUntil); lockedUntil != "" {
		ts, parseErr := time.Parse(time.RFC3339, lockedUntil)
		if parseErr == nil && time.Now().Before(ts) {
			return fmt.Errorf("vault locked until %s due to too many failed unlock attempts", ts.Format(time.Kitchen))
		}
	}

	rawKey, err := v.kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}

	kdfVersion, err := v.readKDFVersion(ctx)
	if err != nil {
		return err
	}
	var key []byte
	switch kdfVersion {
	case 1:
		key, err = v.enc.KeyToBuffer(rawKey)
	case crypto.KDFVersion2:
		var saltB64 string
		saltB64, metaErr := v.store.GetMeta(ctx, "kdf_salt")
		if metaErr != nil {
			return fmt.Errorf("get kdf_salt: %w", metaErr)
		}
		if saltB64 == "" {
			return errors.New("vault corrupted: kdf_salt missing for V2 vault")
		}
		var salt []byte
		salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
		if decodeErr != nil {
			return fmt.Errorf("decode kdf_salt: %w", decodeErr)
		}
		key, err = v.enc.KeyToBufferV2WithSalt(rawKey, salt)
	default:
		return fmt.Errorf("unsupported KDF version: %d", kdfVersion)
	}
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	all, verifyErr := v.store.GetAllSecrets(ctx)
	if verifyErr != nil {
		return fmt.Errorf("verify vault: %w", verifyErr)
	}

	verifyIV, ivErr := v.store.GetMeta(ctx, "verify_iv")
	verifyData, dataErr := v.store.GetMeta(ctx, "verify_data")

	verified := false
	if ivErr == nil && dataErr == nil && verifyIV != "" && verifyData != "" {
		ivBytes, ivDecodeErr := base64.StdEncoding.DecodeString(verifyIV)
		if ivDecodeErr != nil {
			return fmt.Errorf("decode verify_iv: %w", ivDecodeErr)
		}
		dataBytes, dataDecodeErr := base64.StdEncoding.DecodeString(verifyData)
		if dataDecodeErr != nil {
			return fmt.Errorf("decode verify_data: %w", dataDecodeErr)
		}
		if _, decErr := v.enc.Decrypt(dataBytes, ivBytes, key); decErr != nil {
			return v.failUnlock(ctx, key)
		}
		verified = true
	} else if len(all) > 0 {
		if _, decErr := v.enc.Decrypt(all[0].EncryptedValue, all[0].IV, key); decErr != nil {
			return v.failUnlock(ctx, key)
		}
		verified = true
	}

	v.mu.Lock()
	v.key = key
	v.mu.Unlock()

	if verified {
		_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
		_ = v.store.SetMeta(ctx, metaUnlockLockedUntil, "")
		_ = v.store.SetMeta(ctx, metaUnlockCycle, "0")
	}
	return nil
}
```

Update `failUnlock` to accept the key parameter:

```go
func (v *Vault) failUnlock(ctx context.Context, key []byte) error {
	crypto.ZeroBytes(key)
	attempts, _ := v.store.IncrementMetaInt(ctx, metaUnlockAttempts, 1)
	if attempts >= maxUnlockAttempts {
		cycle := 0
		if cycleStr, cycleErr := v.store.GetMeta(ctx, metaUnlockCycle); cycleErr == nil {
			if n, e := strconv.Atoi(cycleStr); e == nil {
				cycle = n
			}
		}

		lockDuration := min(
			time.Duration(unlockDelayBaseMs)*time.Millisecond*time.Duration(1<<uint(cycle)),
			maxLockDuration,
		)
		lockedUntil := time.Now().Add(lockDuration)
		_ = v.store.SetMeta(ctx, metaUnlockLockedUntil, lockedUntil.Format(time.RFC3339))
		_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
		_ = v.store.SetMeta(ctx, metaUnlockCycle, strconv.Itoa(cycle+1))
	}
	return errors.New("authentication failed")
}
```

- [ ] **Step 4: Run all vault tests**

Run: `go test ./internal/vault/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "fix: verify key before storing in Vault to prevent TOCTOU"
```

---

### Task 3: Silent init failure (S-3)

**Files:**
- Modify: `internal/vault/vault.go:119-123`
- Test: `internal/vault/vault_test.go`

- [ ] **Step 1: Write failing test**

Add to `internal/vault/vault_test.go`:

```go
func TestInitVault_ReturnsErrorWithoutKey(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	enc := crypto.NewAESGCM()

	kp := &testKeyProvider{enc: enc, key: nil}

	ctx := context.Background()
	err := InitVault(ctx, dbPath, enc, kp, InitOptions{SkipKeychain: true})
	if err == nil {
		t.Fatal("InitVault should return error when no key is available")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run TestInitVault_ReturnsErrorWithoutKey -v`
Expected: FAIL — InitVault returns nil

- [ ] **Step 3: Fix InitVault to return error**

In `internal/vault/vault.go`, change lines 119-123 from:

```go
	rawKey, err = kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return nil
	}
```

to:

```go
	rawKey, err = kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("no key available: set PSST_PASSWORD or ensure keychain is accessible: %w", err)
	}
```

- [ ] **Step 4: Run all vault tests**

Run: `go test ./internal/vault/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "fix: return error when InitVault has no key source"
```

---

## Phase 2: Split vault.go

### Task 4: Create validation.go

**Files:**
- Create: `internal/vault/validation.go`
- Modify: `internal/vault/vault.go` (remove constants + regex)

- [ ] **Step 1: Create validation.go**

```go
package vault

import (
	"fmt"
	"regexp"
)

const (
	maxSecretNameLen  = 256
	maxSecretValueLen = 4096
	maxTags           = 20
)

var secretNameRegex = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

var tagRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func ValidateSecretName(name string) error {
	if len(name) > maxSecretNameLen {
		return fmt.Errorf("secret name too long: max %d bytes", maxSecretNameLen)
	}
	if !secretNameRegex.MatchString(name) {
		return fmt.Errorf("invalid secret name %q: must match %s", name, secretNameRegex.String())
	}
	return nil
}

func ValidateTags(tags []string) error {
	if len(tags) > maxTags {
		return fmt.Errorf("too many tags: max %d", maxTags)
	}
	for _, t := range tags {
		if !tagRegex.MatchString(t) {
			return fmt.Errorf("invalid tag %q: must match %s", t, tagRegex.String())
		}
	}
	return nil
}
```

- [ ] **Step 2: Remove constants and regex from vault.go**

In `internal/vault/vault.go`, remove lines 32-48 (the const block and secretNameRegex). The constants and regex are now in `validation.go`.

- [ ] **Step 3: Update SetSecret to use ValidateSecretName and ValidateTags**

In `internal/vault/vault.go`, replace the name/value validation in `SetSecret` (lines 277-285) with:

```go
	if err := ValidateSecretName(name); err != nil {
		return err
	}
	if len(value) > maxSecretValueLen {
		return fmt.Errorf("secret value too long: max %d bytes", maxSecretValueLen)
	}
	if err := ValidateTags(tags); err != nil {
		return err
	}
```

Note: `ValidateSecretName` already checks both length and regex.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/vault/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/vault/validation.go internal/vault/vault.go
git commit -m "refactor: extract validation functions from vault.go"
```

---

### Task 5: Split vault.go into focused files

**Files:**
- Create: `internal/vault/path.go`
- Create: `internal/vault/init.go`
- Create: `internal/vault/unlock.go`
- Create: `internal/vault/secrets.go`
- Create: `internal/vault/history.go`
- Create: `internal/vault/tags.go`
- Create: `internal/vault/migrate.go`
- Modify: `internal/vault/vault.go`

This is the largest task. Each new file gets specific functions from vault.go with appropriate imports.

- [ ] **Step 1: Create path.go**

```go
package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

func FindVaultPath(global bool, env string) (string, error) {
	if env != "" && !envNameRegex.MatchString(env) {
		return "", fmt.Errorf("invalid env name %q: must match %s", env, envNameRegex.String())
	}

	baseDir := ".psst"
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home dir: %w", err)
		}
		baseDir = filepath.Join(home, ".psst")
	}

	if env != "" {
		baseDir = filepath.Join(baseDir, "envs", env)
	}

	return filepath.Join(baseDir, "vault.db"), nil
}
```

- [ ] **Step 2: Create init.go**

```go
package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)

func InitVault(
	ctx context.Context,
	vaultPath string,
	enc crypto.Encryptor,
	kp keyring.KeyProvider,
	opts InitOptions,
) error {
	dir := filepath.Dir(vaultPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	s, err := store.NewSQLite(vaultPath)
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	defer s.Close()

	if err = s.InitSchema(); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}

	if err = s.SetMeta(ctx, "kdf_version", strconv.Itoa(crypto.CurrentKDFVersion)); err != nil {
		return fmt.Errorf("set vault metadata: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err = rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	if err = s.SetMeta(ctx, "kdf_salt", base64.StdEncoding.EncodeToString(salt)); err != nil {
		return fmt.Errorf("set kdf salt: %w", err)
	}

	var rawKey string
	if !opts.SkipKeychain && !keyring.IsEnvProvider(kp) {
		var key []byte
		key, err = kp.GenerateKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		if err = kp.SetKey(serviceName, accountName, key); err != nil {
			return fmt.Errorf("store key in keychain: %w", err)
		}
		rawKey = hex.EncodeToString(key)
	} else {
		rawKey, err = kp.GetRawKey(serviceName, accountName)
		if err != nil {
			return fmt.Errorf("no key available: set PSST_PASSWORD or ensure keychain is accessible: %w", err)
		}
	}

	derivedKey, deriveErr := enc.KeyToBufferV2WithSalt(rawKey, salt)
	if deriveErr != nil {
		return fmt.Errorf("derive verification key: %w", deriveErr)
	}

	verifyCiphertext, verifyIV, encErr := enc.Encrypt([]byte("psst-verify"), derivedKey)
	if encErr != nil {
		return fmt.Errorf("create verification: %w", encErr)
	}

	if metaErr := s.SetMeta(ctx, "verify_iv", base64.StdEncoding.EncodeToString(verifyIV)); metaErr != nil {
		return fmt.Errorf("set verify_iv: %w", metaErr)
	}
	if metaErr := s.SetMeta(ctx, "verify_data", base64.StdEncoding.EncodeToString(verifyCiphertext)); metaErr != nil {
		return fmt.Errorf("set verify_data: %w", metaErr)
	}

	return nil
}
```

- [ ] **Step 3: Create unlock.go**

```go
package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
)

func (v *Vault) Unlock(ctx context.Context) error {
	if err := v.checkLockout(ctx); err != nil {
		return err
	}

	rawKey, err := v.kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}

	key, kdfVersion, deriveErr := v.deriveKey(ctx, rawKey)
	if deriveErr != nil {
		return deriveErr
	}

	if kdfVersion == 1 {
		fmt.Fprintf(os.Stderr, "warning: vault uses deprecated KDF (SHA-256). Run 'psst migrate' to upgrade to Argon2id.\n")
	}

	all, verifyErr := v.store.GetAllSecrets(ctx)
	if verifyErr != nil {
		return fmt.Errorf("verify vault: %w", verifyErr)
	}

	if err = v.verifyKey(ctx, key, all); err != nil {
		return err
	}

	v.mu.Lock()
	v.key = key
	v.mu.Unlock()

	v.resetFailedAttempts(ctx)
	return nil
}

func (v *Vault) checkLockout(ctx context.Context) error {
	lockedUntil, _ := v.store.GetMeta(ctx, metaUnlockLockedUntil)
	if lockedUntil == "" {
		return nil
	}
	ts, parseErr := time.Parse(time.RFC3339, lockedUntil)
	if parseErr == nil && time.Now().Before(ts) {
		return fmt.Errorf("vault locked until %s due to too many failed unlock attempts", ts.Format(time.Kitchen))
	}
	return nil
}

func (v *Vault) deriveKey(ctx context.Context, rawKey string) ([]byte, int, error) {
	kdfVersion, err := v.readKDFVersion(ctx)
	if err != nil {
		return nil, 0, err
	}
	var key []byte
	switch kdfVersion {
	case 1:
		key, err = v.enc.KeyToBuffer(rawKey)
	case crypto.KDFVersion2:
		var saltB64 string
		saltB64, metaErr := v.store.GetMeta(ctx, "kdf_salt")
		if metaErr != nil {
			return nil, 0, fmt.Errorf("get kdf_salt: %w", metaErr)
		}
		if saltB64 == "" {
			return nil, 0, errors.New("vault corrupted: kdf_salt missing for V2 vault")
		}
		var salt []byte
		salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
		if decodeErr != nil {
			return nil, 0, fmt.Errorf("decode kdf_salt: %w", decodeErr)
		}
		key, err = v.enc.KeyToBufferV2WithSalt(rawKey, salt)
	default:
		return nil, 0, fmt.Errorf("unsupported KDF version: %d", kdfVersion)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("derive key: %w", err)
	}
	return key, kdfVersion, nil
}

func (v *Vault) verifyKey(ctx context.Context, key []byte, all []StoredSecret) error {
	verifyIV, ivErr := v.store.GetMeta(ctx, "verify_iv")
	verifyData, dataErr := v.store.GetMeta(ctx, "verify_data")

	if ivErr == nil && dataErr == nil && verifyIV != "" && verifyData != "" {
		ivBytes, ivDecodeErr := base64.StdEncoding.DecodeString(verifyIV)
		if ivDecodeErr != nil {
			crypto.ZeroBytes(key)
			return fmt.Errorf("decode verify_iv: %w", ivDecodeErr)
		}
		dataBytes, dataDecodeErr := base64.StdEncoding.DecodeString(verifyData)
		if dataDecodeErr != nil {
			crypto.ZeroBytes(key)
			return fmt.Errorf("decode verify_data: %w", dataDecodeErr)
		}
		if _, decErr := v.enc.Decrypt(dataBytes, ivBytes, key); decErr != nil {
			return v.failUnlock(ctx, key)
		}
		return nil
	}

	if len(all) > 0 {
		if _, decErr := v.enc.Decrypt(all[0].EncryptedValue, all[0].IV, key); decErr != nil {
			return v.failUnlock(ctx, key)
		}
	}
	return nil
}

func (v *Vault) resetFailedAttempts(ctx context.Context) {
	_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
	_ = v.store.SetMeta(ctx, metaUnlockLockedUntil, "")
	_ = v.store.SetMeta(ctx, metaUnlockCycle, "0")
}

func (v *Vault) failUnlock(ctx context.Context, key []byte) error {
	crypto.ZeroBytes(key)
	attempts, _ := v.store.IncrementMetaInt(ctx, metaUnlockAttempts, 1)
	if attempts >= maxUnlockAttempts {
		cycle := 0
		if cycleStr, cycleErr := v.store.GetMeta(ctx, metaUnlockCycle); cycleErr == nil {
			if n, e := strconv.Atoi(cycleStr); e == nil {
				cycle = n
			}
		}

		lockDuration := min(
			time.Duration(unlockDelayBaseMs)*time.Millisecond*time.Duration(1<<uint(cycle)),
			maxLockDuration,
		)
		lockedUntil := time.Now().Add(lockDuration)
		_ = v.store.SetMeta(ctx, metaUnlockLockedUntil, lockedUntil.Format(time.RFC3339))
		_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
		_ = v.store.SetMeta(ctx, metaUnlockCycle, strconv.Itoa(cycle+1))
	}
	return errors.New("authentication failed")
}

func (v *Vault) readKDFVersion(ctx context.Context) (int, error) {
	val, err := v.store.GetMeta(ctx, "kdf_version")
	if err != nil {
		return 0, fmt.Errorf("get kdf_version: %w", err)
	}
	if val == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("corrupted kdf_version: %q: %w", val, err)
	}
	if n < 1 || n > 2 {
		return 0, fmt.Errorf("unsupported KDF version: %d", n)
	}
	return n, nil
}
```

Note: unlock.go needs `"os"` added to imports for the V1 warning `fmt.Fprintf(os.Stderr, ...)`.

The `verifyKey` function references `StoredSecret` — add import `"github.com/aatumaykin/psst/internal/store"` to unlock.go.

Full imports for unlock.go:

```go
import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/store"
)
```

And change `all []StoredSecret` to `all []store.StoredSecret` in `verifyKey`.

- [ ] **Step 4: Create secrets.go**

```go
package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/store"
)

var ErrSecretNotFound = errors.New("secret not found")

func (v *Vault) SetSecret(ctx context.Context, name string, value []byte, tags []string) error {
	v.mu.RLock()
	key := v.key
	v.mu.RUnlock()
	if key == nil {
		return errors.New("vault is locked")
	}

	if err := ValidateSecretName(name); err != nil {
		return err
	}
	if len(value) > maxSecretValueLen {
		return fmt.Errorf("secret value too long: max %d bytes", maxSecretValueLen)
	}
	if err := ValidateTags(tags); err != nil {
		return err
	}

	return v.store.ExecTx(func() error {
		existing, err := v.store.GetSecret(ctx, name)
		if err != nil {
			return fmt.Errorf("get existing secret: %w", err)
		}
		if existing != nil {
			var history []store.HistoryEntry
			history, err = v.store.GetHistory(ctx, name)
			if err != nil {
				return fmt.Errorf("get history: %w", err)
			}
			version := maxVersion(history) + 1
			if err = v.store.AddHistory(ctx,
				name, version,
				existing.EncryptedValue, existing.IV, existing.Tags,
			); err != nil {
				return fmt.Errorf("archive history: %w", err)
			}
			if err = v.store.PruneHistory(ctx, name, maxHistory); err != nil {
				return fmt.Errorf("prune history: %w", err)
			}
		}

		ciphertext, iv, err := v.enc.Encrypt(value, key)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		return v.store.SetSecret(ctx, name, ciphertext, iv, tags)
	})
}

func (v *Vault) GetSecret(ctx context.Context, name string) (*Secret, error) {
	v.mu.RLock()
	key := v.key
	v.mu.RUnlock()
	if key == nil {
		return nil, errors.New("vault is locked")
	}

	stored, err := v.store.GetSecret(ctx, name)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, ErrSecretNotFound
	}

	plaintext, err := v.enc.Decrypt(stored.EncryptedValue, stored.IV, key)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return &Secret{
		Name:      stored.Name,
		Value:     plaintext,
		Tags:      stored.Tags,
		CreatedAt: stored.CreatedAt,
		UpdatedAt: stored.UpdatedAt,
	}, nil
}

func (v *Vault) ListSecrets(ctx context.Context) ([]SecretMeta, error) {
	if err := v.requireUnlock(); err != nil {
		return nil, err
	}
	storeMetas, err := v.store.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]SecretMeta, len(storeMetas))
	for i, m := range storeMetas {
		result[i] = SecretMeta{
			Name:      m.Name,
			Tags:      m.Tags,
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		}
	}
	return result, nil
}

func (v *Vault) DeleteSecret(ctx context.Context, name string) error {
	if err := v.requireUnlock(); err != nil {
		return err
	}
	return v.store.ExecTx(func() error {
		if err := v.store.DeleteSecret(ctx, name); err != nil {
			return err
		}
		return v.store.DeleteHistory(ctx, name)
	})
}

func (v *Vault) GetAllSecrets(ctx context.Context) (map[string][]byte, error) {
	v.mu.RLock()
	key := v.key
	v.mu.RUnlock()
	if key == nil {
		return nil, errors.New("vault is locked")
	}

	all, err := v.store.GetAllSecrets(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte, len(all))
	for _, s := range all {
		var plaintext []byte
		plaintext, err = v.enc.Decrypt(s.EncryptedValue, s.IV, key)
		if err != nil {
			for k, v := range result {
				crypto.ZeroBytes(v)
				delete(result, k)
			}
			return nil, fmt.Errorf("decrypt secret: %w", err)
		}
		result[s.Name] = plaintext
	}
	return result, nil
}
```

- [ ] **Step 5: Create history.go**

```go
package vault

import (
	"context"
	"fmt"

	"github.com/aatumaykin/psst/internal/store"
)

func (v *Vault) GetHistory(ctx context.Context, name string) ([]SecretHistoryEntry, error) {
	if err := v.requireUnlock(); err != nil {
		return nil, err
	}
	entries, err := v.store.GetHistory(ctx, name)
	if err != nil {
		return nil, err
	}
	result := make([]SecretHistoryEntry, len(entries))
	for i, e := range entries {
		result[i] = SecretHistoryEntry{
			Version:    e.Version,
			Tags:       e.Tags,
			ArchivedAt: e.ArchivedAt,
		}
	}
	return result, nil
}

func (v *Vault) Rollback(ctx context.Context, name string, version int) error {
	if err := v.requireUnlock(); err != nil {
		return err
	}

	return v.store.ExecTx(func() error {
		current, err := v.store.GetSecret(ctx, name)
		if err != nil {
			return err
		}
		if current == nil {
			return fmt.Errorf("secret %q not found", name)
		}

		history, err := v.store.GetHistory(ctx, name)
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

		newVersion := maxVersion(history) + 1
		if err = v.store.AddHistory(
			ctx,
			name,
			newVersion,
			current.EncryptedValue,
			current.IV,
			current.Tags,
		); err != nil {
			return fmt.Errorf("archive history: %w", err)
		}
		if err = v.store.PruneHistory(ctx, name, maxHistory); err != nil {
			return fmt.Errorf("prune history: %w", err)
		}
		return v.store.SetSecret(ctx, name, target.EncryptedValue, target.IV, target.Tags)
	})
}

func maxVersion(entries []store.HistoryEntry) int {
	maxV := 0
	for _, h := range entries {
		if h.Version > maxV {
			maxV = h.Version
		}
	}
	return maxV
}
```

- [ ] **Step 6: Create tags.go**

```go
package vault

import (
	"context"
	"fmt"
	"slices"
)

func (v *Vault) AddTag(ctx context.Context, name string, tag string) error {
	if err := v.requireUnlock(); err != nil {
		return err
	}

	return v.store.ExecTx(func() error {
		sec, err := v.store.GetSecret(ctx, name)
		if err != nil {
			return err
		}
		if sec == nil {
			return fmt.Errorf("secret %q not found", name)
		}

		if slices.Contains(sec.Tags, tag) {
			return nil
		}
		sec.Tags = append(sec.Tags, tag)
		return v.store.SetSecret(ctx, name, sec.EncryptedValue, sec.IV, sec.Tags)
	})
}

func (v *Vault) RemoveTag(ctx context.Context, name string, tag string) error {
	if err := v.requireUnlock(); err != nil {
		return err
	}

	return v.store.ExecTx(func() error {
		sec, err := v.store.GetSecret(ctx, name)
		if err != nil {
			return err
		}
		if sec == nil {
			return fmt.Errorf("secret %q not found", name)
		}

		filtered := make([]string, 0, len(sec.Tags))
		for _, t := range sec.Tags {
			if t != tag {
				filtered = append(filtered, t)
			}
		}
		sec.Tags = filtered
		return v.store.SetSecret(ctx, name, sec.EncryptedValue, sec.IV, sec.Tags)
	})
}

func (v *Vault) GetSecretsByTags(ctx context.Context, tags []string) ([]SecretMeta, error) {
	all, err := v.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}

	if len(tags) == 0 {
		return all, nil
	}

	var result []SecretMeta
	for _, s := range all {
		for _, wantTag := range tags {
			if slices.Contains(s.Tags, wantTag) {
				result = append(result, s)
				break
			}
		}
	}
	return result, nil
}

func (v *Vault) GetSecretNamesByTags(ctx context.Context, tags []string) ([]string, error) {
	metas, err := v.GetSecretsByTags(ctx, tags)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(metas))
	for i, m := range metas {
		names[i] = m.Name
	}
	return names, nil
}

func (v *Vault) GetSecretsByTagValues(ctx context.Context, tags []string) (map[string][]byte, error) {
	names, err := v.GetSecretNamesByTags(ctx, tags)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]byte, len(names))
	for _, name := range names {
		sec, secErr := v.GetSecret(ctx, name)
		if secErr != nil {
			return nil, fmt.Errorf("get secret: %w", secErr)
		}
		result[name] = sec.Value
	}
	return result, nil
}
```

- [ ] **Step 7: Create migrate.go**

Move `MigrateKDF` from vault.go (lines 619-691) to `internal/vault/migrate.go`. The code is identical — just move it with its imports.

- [ ] **Step 8: Reduce vault.go to essentials**

After splitting, `internal/vault/vault.go` should contain only:

```go
package vault

import (
	"context"
	"errors"
	"sync"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)

type Vault struct {
	mu    sync.RWMutex
	enc   crypto.Encryptor
	kp    keyring.KeyProvider
	store store.SecretStore
	key   []byte
}

const (
	serviceName           = "psst"
	accountName           = "vault-key"
	maxHistory            = 10
	saltSize              = 16
	maxUnlockAttempts     = 10
	unlockDelayBaseMs     = 500
	maxLockDuration       = 5 * time.Minute
	metaUnlockAttempts    = "unlock_attempts"
	metaUnlockLockedUntil = "unlock_locked_until"
	metaUnlockCycle       = "unlock_cycle"
)

func New(enc crypto.Encryptor, kp keyring.KeyProvider, s store.SecretStore) *Vault {
	return &Vault{enc: enc, kp: kp, store: s}
}

func (v *Vault) Close() error {
	v.mu.Lock()
	crypto.ZeroBytes(v.key)
	v.key = nil
	v.mu.Unlock()
	return v.store.Close()
}

func (v *Vault) requireUnlock() error {
	v.mu.RLock()
	unlocked := v.key != nil
	v.mu.RUnlock()
	if !unlocked {
		return errors.New("vault is locked: unlock required")
	}
	return nil
}
```

Note: vault.go needs `"time"` in imports for `maxLockDuration`.

Full imports for vault.go:

```go
import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)
```

- [ ] **Step 9: Run all tests**

Run: `go test ./... -v`
Expected: ALL PASS — this is a pure refactor, no behavior changes

- [ ] **Step 10: Commit**

```bash
git add internal/vault/
git commit -m "refactor: split vault.go into focused files"
```

---

## Phase 3: Architecture — vault.Open() + VaultInterface

### Task 6: Add VaultInterface and vault.Open()

**Files:**
- Create: `internal/vault/interface.go`
- Modify: `internal/vault/vault.go` (add Open function)
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Create interface.go**

```go
package vault

import "context"

type VaultInterface interface {
	Unlock(ctx context.Context) error
	GetSecret(ctx context.Context, name string) (*Secret, error)
	SetSecret(ctx context.Context, name string, value []byte, tags []string) error
	ListSecrets(ctx context.Context) ([]SecretMeta, error)
	DeleteSecret(ctx context.Context, name string) error
	GetAllSecrets(ctx context.Context) (map[string][]byte, error)
	GetHistory(ctx context.Context, name string) ([]SecretHistoryEntry, error)
	Rollback(ctx context.Context, name string, version int) error
	AddTag(ctx context.Context, name, tag string) error
	RemoveTag(ctx context.Context, name, tag string) error
	GetSecretsByTags(ctx context.Context, tags []string) ([]SecretMeta, error)
	GetSecretNamesByTags(ctx context.Context, tags []string) ([]string, error)
	GetSecretsByTagValues(ctx context.Context, tags []string) (map[string][]byte, error)
	MigrateKDF(ctx context.Context) error
	Close() error
}
```

- [ ] **Step 2: Add Open() to vault.go**

Add to `internal/vault/vault.go`:

```go
func Open(vaultPath string) (*Vault, error) {
	enc := crypto.NewAESGCM()
	kp := keyring.NewProvider(enc)

	s, err := store.NewSQLite(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	if err = s.InitSchema(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return New(enc, kp, s), nil
}
```

Add `"fmt"` to vault.go imports.

- [ ] **Step 3: Refactor getUnlockedVault in root.go**

Replace the entire `getUnlockedVault` function and remove `createDependencies`:

```go
const (
	ExitSuccess    = 0
	ExitError      = 1
	ExitNoVault    = 3
	ExitAuthFailed = 5
)

func getUnlockedVault(ctx context.Context, jsonOut, quiet, global bool, env string) (vault.VaultInterface, error) {
	vaultPath, err := vault.FindVaultPath(global, env)
	if err != nil {
		return nil, err
	}

	//nolint:gosec // user-provided path is intentional for CLI tool
	if _, statErr := os.Stat(vaultPath); os.IsNotExist(statErr) {
		printNoVault(jsonOut, quiet)
		return nil, &exitError{code: ExitNoVault}
	}

	v, err := vault.Open(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}

	if unlockErr := v.Unlock(ctx); unlockErr != nil {
		_ = v.Close()
		printAuthFailed(jsonOut, quiet)
		return nil, &exitError{code: ExitAuthFailed}
	}
	return v, nil
}
```

Remove `createDependencies()` function entirely.

Update imports in root.go — remove:
- `"github.com/aatumaykin/psst/internal/crypto"`
- `"github.com/aatumaykin/psst/internal/keyring"`
- `"github.com/aatumaykin/psst/internal/store"`

The root.go should now import:
```go
import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/runner"
	"github.com/aatumaykin/psst/internal/vault"
)
```

Note: `keyring` import is still needed for `keyring.IsKeychainAvailable()` in `printAuthFailed`.

- [ ] **Step 4: Update init.go CLI command**

In `internal/cli/init.go`, replace `createDependencies()` call:

```go
enc, kp := createDependencies()
```

with:

```go
enc := crypto.NewAESGCM()
kp := keyring.NewProvider(enc)
```

And add imports:
```go
"github.com/aatumaykin/psst/internal/crypto"
"github.com/aatumaykin/psst/internal/keyring"
```

(Remove `"github.com/aatumaykin/psst/internal/vault"` if already present — no, keep it, `vault.FindVaultPath` and `vault.InitVault` are still used.)

Actually, init.go already imports keyring and vault. Just need to add crypto import and remove the createDependencies call.

- [ ] **Step 5: Run all tests**

Run: `go test ./... -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add internal/vault/interface.go internal/vault/vault.go internal/cli/root.go internal/cli/init.go
git commit -m "refactor: add VaultInterface and vault.Open() factory"
```

---

## Phase 4: CLI refactoring

### Task 7: Named exit constants + remove validName from CLI + withVault helper

**Files:**
- Modify: `internal/cli/root.go`
- Modify: `internal/cli/set.go`
- Modify: `internal/cli/get.go`
- Modify: `internal/cli/rm.go`
- Modify: `internal/cli/history.go`
- Modify: `internal/cli/rollback.go`
- Modify: `internal/cli/tag.go`
- Modify: `internal/cli/import.go`
- Modify: `internal/cli/exec.go`
- Modify: `internal/cli/run.go`
- Modify: `internal/cli/export.go`
- Modify: `internal/cli/scan.go`
- Modify: `internal/cli/migrate.go`
- Modify: `internal/cli/args.go`

- [ ] **Step 1: Add withVault helper and exit constants to root.go**

Exit constants were added in Task 6. Add `withVault`:

```go
func withVault(cmd *cobra.Command, fn func(v vault.VaultInterface, f *output.Formatter) error) error {
	jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
	v, err := getUnlockedVault(cmd.Context(), jsonOut, quiet, global, env)
	if err != nil {
		return err
	}
	defer v.Close()
	f := getFormatter(jsonOut, quiet)
	return fn(v, f)
}
```

- [ ] **Step 2: Remove validName regex from set.go**

In `internal/cli/set.go`, remove line 14:
```go
var validName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
```

And the `"regexp"` import.

Replace all `validName.MatchString(name)` with `vault.ValidateSecretName(name) == nil` throughout all CLI files.

Add `"github.com/aatumaykin/psst/internal/vault"` import where needed.

Files using `validName`:
- `set.go` — line 25
- `get.go` — line 18
- `rm.go` — line 19
- `history.go` — line 22
- `rollback.go` — line 19
- `tag.go` — lines 19, 48
- `import.go` — lines 65, 133
- `exec.go` — line 37

Replace `!validName.MatchString(name)` with `vault.ValidateSecretName(name) != nil` in each.

- [ ] **Step 3: Refactor commands to use withVault**

Example — refactor `get.go`:

```go
var getCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get a secret value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := vault.ValidateSecretName(name); err != nil {
			return exitWithError(fmt.Sprintf("Invalid secret name %q", name))
		}
		return withVault(cmd, func(v vault.VaultInterface, f *output.Formatter) error {
			sec, err := v.GetSecret(cmd.Context(), name)
			if err != nil {
				return exitWithError(err.Error())
			}
			f.SecretValue(name, string(sec.Value))
			return nil
		})
	},
}
```

Apply similar pattern to: `set.go`, `rm.go`, `list.go`, `history.go`, `rollback.go`, `tag.go`, `export.go`, `scan.go`, `migrate.go`, `run.go`.

For `list.go` and `scan.go` which also need tags, extract them before calling `withVault`.

- [ ] **Step 4: Fix filterSecretNames dead parameters**

In `internal/cli/args.go`, simplify the signature:

```go
func filterSecretNames(args []string) []string {
```

Remove the 4 unused parameters. Update the call site in `root.go`:
```go
secretNames := filterSecretNames(args[:dashDashIdx])
```

- [ ] **Step 5: Add ExecConfig struct for exec.go**

Replace the 9-parameter `handleExecPatternDirect` with:

```go
type ExecConfig struct {
	JSONOut bool
	Quiet   bool
	Global  bool
	Env     string
	Tags    []string
	NoMask  bool
}

func handleExecPatternDirect(
	ctx context.Context,
	secretNames []string,
	commandArgs []string,
	cfg ExecConfig,
) error {
```

Update the call site in `Execute()` (root.go) accordingly.

- [ ] **Step 6: Use Formatter in update.go**

Replace `fmt.Fprintf(os.Stdout, ...)` calls with Formatter methods. For `updateCheckCmd` and `updateInstallCmd`, extract formatter early and use it consistently.

- [ ] **Step 7: Run all tests**

Run: `go test ./... -v`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add internal/cli/
git commit -m "refactor: CLI uses withVault, ValidateSecretName, named exit constants"
```

---

## Phase 5: Robustness

### Task 8: PRAGMA integrity_check + PSST_PASSWORD fallback + ZeroBytes + ExecTx doc

**Files:**
- Modify: `internal/store/sqlite.go`
- Modify: `internal/keyring/oskeyring.go`
- Modify: `internal/crypto/aesgcm.go`

- [ ] **Step 1: Add PRAGMA integrity_check to NewSQLite**

In `internal/store/sqlite.go`, after the `PingContext` check (line 37), add:

```go
	var integrity string
	if intErr := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); intErr != nil || integrity != "ok" {
		_ = db.Close()
		if intErr != nil {
			return nil, fmt.Errorf("vault integrity check failed: %w", intErr)
		}
		return nil, fmt.Errorf("vault integrity check failed: %s", integrity)
	}
```

- [ ] **Step 2: Add PSST_PASSWORD fallback in oskeyring.go**

In `internal/keyring/oskeyring.go`, update `GetRawKey`:

```go
func (o *OSKeyring) GetRawKey(service, account string) (string, error) {
	encoded, err := keyring.Get(service, account)
	if err == nil {
		return encoded, nil
	}
	if pw := os.Getenv("PSST_PASSWORD"); pw != "" {
		return pw, nil
	}
	return "", fmt.Errorf("keychain unavailable and PSST_PASSWORD not set: %w", err)
}
```

Add `"os"` to imports.

- [ ] **Step 3: Add runtime.KeepAlive to ZeroBytes**

In `internal/crypto/aesgcm.go`, update `ZeroBytes`:

```go
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
```

Add `"runtime"` to imports.

- [ ] **Step 4: Add ExecTx documentation**

In `internal/store/sqlite.go`, add doc comment to `ExecTx`:

```go
// ExecTx executes fn within a database transaction.
// fn MUST NOT call ExecTx recursively — the mutex is not reentrant.
func (s *SQLiteStore) ExecTx(fn func() error) error {
```

- [ ] **Step 5: Run all tests**

Run: `go test ./... -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add internal/store/sqlite.go internal/keyring/oskeyring.go internal/crypto/aesgcm.go
git commit -m "fix: integrity check on open, PSST_PASSWORD fallback, ZeroBytes hardening"
```

---

## Phase 6: Tests

### Task 9: Add security and robustness tests

**Files:**
- Modify: `internal/vault/vault_test.go`
- Modify: `internal/store/sqlite_test.go`

- [ ] **Step 1: Add corrupted vault test**

In `internal/store/sqlite_test.go`:

```go
func TestCorruptedVault(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "corrupt.db")

	data := []byte("this is not a valid sqlite database")
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := NewSQLite(dbPath)
	if err == nil {
		t.Fatal("should reject corrupted database")
	}
}
```

- [ ] **Step 2: Add name boundary test**

In `internal/vault/vault_test.go`:

```go
func TestSetSecret_NameExactly256Bytes(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	name := strings.Repeat("A", 256)
	err := v.SetSecret(ctx, name, []byte("val"), nil)
	if err != nil {
		t.Fatalf("256-byte name should be accepted: %v", err)
	}
}
```

- [ ] **Step 3: Add null bytes in value test**

In `internal/vault/vault_test.go`:

```go
func TestSetGetSecret_NullBytes(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	value := []byte("hello\x00world")
	if err := v.SetSecret(ctx, "BIN_KEY", value, nil); err != nil {
		t.Fatal(err)
	}

	sec, err := v.GetSecret(ctx, "BIN_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sec.Value, value) {
		t.Fatalf("value mismatch: got %q, want %q", sec.Value, value)
	}
}
```

Add `"bytes"` import to test file.

- [ ] **Step 4: Add ValidateTags test**

In `internal/vault/vault_test.go`:

```go
func TestValidateTags(t *testing.T) {
	if err := ValidateTags([]string{"aws", "prod-1", "test_env"}); err != nil {
		t.Fatalf("valid tags: %v", err)
	}
	if err := ValidateTags(nil); err != nil {
		t.Fatalf("nil tags: %v", err)
	}
	if err := ValidateTags(make([]string, 21)); err == nil {
		t.Fatal("too many tags should fail")
	}
	if err := ValidateTags([]string{"invalid tag!"}); err == nil {
		t.Fatal("invalid tag should fail")
	}
}
```

- [ ] **Step 5: Add concurrent access test**

In `internal/vault/vault_test.go`:

```go
func TestConcurrentAccess(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "KEY", []byte("initial"), nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			v.GetSecret(ctx, "KEY")
		}
	}()
	for i := range 50 {
		v.SetSecret(ctx, "KEY", []byte(fmt.Sprintf("v%d", i)), nil)
	}
	<-done
}
```

- [ ] **Step 6: Run all tests**

Run: `go test ./... -v -race`
Expected: ALL PASS, no race conditions

- [ ] **Step 7: Commit**

```bash
git add internal/vault/vault_test.go internal/store/sqlite_test.go
git commit -m "test: add security, boundary, concurrency, and corruption tests"
```

---

### Task 10: Final verification + backup docs

- [ ] **Step 1: Run full test suite with race detector**

Run: `go test -race ./...`
Expected: ALL PASS

- [ ] **Step 2: Run linter**

Run: `make build`
Expected: Build succeeds

- [ ] **Step 3: Run go vet**

Run: `go vet ./...`
Expected: No issues

- [ ] **Step 4: Add backup section to README**

Add a "Backup & Recovery" section to README.md with:
- Copy `vault.db` to backup location
- For keychain users: note that keychain entry must also be backed up
- For PSST_PASSWORD users: backup is password-based, just keep vault.db + password
- Recovery: copy vault.db back, ensure keychain entry exists or PSST_PASSWORD is set
- Warning: `psst export` writes plaintext

- [ ] **Step 5: Final commit**

```bash
git add README.md
git commit -m "docs: add backup and recovery section"
```

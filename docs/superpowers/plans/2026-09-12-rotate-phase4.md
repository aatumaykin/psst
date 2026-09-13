# `psst rotate` (Phase 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement vault key rotation for git storage: `psst rotate` (new salt + full re-encryption + `psst.yaml` as ONE commit) and `psst sync --accept-rotation` (explicit pin adoption with a password probe), per the approved spec.

**Architecture:** Additive store methods (`ExecTxMsg`, `RotateSalt`, `SyncAcceptRotation`, `AheadOfUpstream`) + `vault.Rotate`/`VerifyAllDecryptable` (re-encryption lives in the vault layer — store stays crypto-free) + two CLI commands. The authoritative secret set is derived INSIDE the transaction (post-pull); acceptance probes on a pin-less store over the same repo. Spec: `docs/superpowers/specs/2026-09-12-rotate-design.md` (approved after 2 review rounds — read §1, §2, §4 before starting).

**Tech Stack:** Go 1.26 stdlib + existing deps (`golang.org/x/term` for prompts). No new dependencies.

## Global Constraints

- Tests run ONLY with `PSST_NO_KEYCHAIN=1` (use `make test`).
- `make test` green before every commit; conventional commits (`feat:`, `test:`, `docs:`).
- No new dependencies (`go.mod` untouched). No comments in code (only `//nolint:`).
- Error wrapping: `fmt.Errorf("context: %w", err)`. Fake secrets only (`"secret123"`, `"test-password"`, `"new-password"`).
- Values never logged; abort errors carry NAMES only.
- Work in worktree `.worktrees/rotate`, branch `feat/rotate`. Module: `github.com/aatumaykin/psst`.

---

### Task 1: store groundwork — `ExecTxMsg`, `RotateSalt`, `SyncAcceptRotation`, `AheadOfUpstream`

**Files:**
- Modify: `internal/store/git.go`
- Test: `internal/store/git_test.go` (extend)

**Interfaces:**
- Produces:
  - `func (g *GitStore) ExecTxMsg(msg string, fn func() error) error` — existing tx machinery, caller-supplied commit subject; `ExecTx` becomes `ExecTxMsg("psst: batch", fn)`.
  - `func (g *GitStore) RotateSalt(saltB64 string) error` — base64/16-byte validation; updates in-memory meta salt; rewrites `psst.yaml` 0600; `git add psst.yaml`; `markDirty`; outside an open tx → error `rotate salt must run inside a transaction`.
  - `func (g *GitStore) SyncAcceptRotation() (*VaultMeta, error)` — repo lock; `pull --rebase --autostash` (conflict → `ErrConflict`); strict-parse disk `psst.yaml`; param check vs `LoadPins()` (same salt → full `CheckPinned`; different salt → reject if any param decreased: wrap `ErrKDFWeakened`); install new meta into the in-memory cache; NEVER touches pins.
  - `func (g *GitStore) AheadOfUpstream() bool` — `git status -sb` first line contains `[ahead`.

- [ ] **Step 1: Write failing tests**

Add to `internal/store/git_test.go`:

```go
func TestGitStoreExecTxMsg(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	err := g.ExecTxMsg("psst: rotate", func() error {
		return g.SetSecret("KEY", []byte("ct"), iv, nil)
	})
	if err != nil {
		t.Fatalf("tx: %v", err)
	}
	out, _ := NewGitRunner(g.repoDir).Run("log", "--format=%s", "-1")
	if strings.TrimSpace(out) != "psst: rotate" {
		t.Fatalf("subject = %q", strings.TrimSpace(out))
	}
}

func TestGitStoreRotateSalt(t *testing.T) {
	g, _ := newGitStore(t)
	if err := g.RotateSalt("MDEyMzQ1Njc4OWFiY2RlZg=="); err == nil {
		t.Fatal("rotate outside tx must fail")
	}
	newSalt := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16))
	err := g.ExecTxMsg("psst: rotate", func() error {
		return g.RotateSalt(newSalt)
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	salt, err := g.GetMeta("kdf_salt")
	if err != nil || salt != newSalt {
		t.Fatalf("salt = %q %v", salt, err)
	}
	if err := g.RotateSalt("c2hvcnQ="); err == nil {
		t.Fatal("short salt must fail")
	}
}

func TestGitStoreSyncAcceptRotationNoRotation(t *testing.T) {
	remote := newBareRemote(t)
	g := newClonedStore(t, remote)
	meta, err := g.SyncAcceptRotation()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	salt, _ := g.GetMeta("kdf_salt")
	if salt != meta.SaltB64 {
		t.Fatalf("cache not updated: %q vs %q", salt, meta.SaltB64)
	}
}

func TestGitStoreSyncAcceptRotationRejectsWeaker(t *testing.T) {
	remote := newBareRemote(t)
	g := newClonedStore(t, remote)
	other, err := NewGitStore(filepath.Join(t.TempDir(), "repo2"), GitOptions{Remote: remote})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := other.SetMeta("kdf_time", "2"); err != nil {
		t.Fatalf("weaken: %v", err)
	}
	err = g.SyncAcceptRotation()
	if !errors.Is(err, ErrKDFWeakened) {
		t.Fatalf("err = %v, want ErrKDFWeakened", err)
	}
}

func TestGitStoreAheadOfUpstream(t *testing.T) {
	remote := newBareRemote(t)
	g := newClonedStore(t, remote)
	if g.AheadOfUpstream() {
		t.Fatal("synced clone must not be ahead")
	}
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, nil); err != nil {
		t.Fatal(err)
	}
	if !g.AheadOfUpstream() {
		t.Fatal("clone with local commit must be ahead")
	}
}
```

(`bytes`, `encoding/base64` may need adding to the test imports.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/store/ -run 'ExecTxMsg|RotateSalt|SyncAcceptRotation|AheadOfUpstream' -v`
Expected: FAIL — undefined methods.

- [ ] **Step 3: Implement**

In `internal/store/git.go`:

```go
func (g *GitStore) ExecTx(fn func() error) error {
	return g.ExecTxMsg("psst: batch", fn)
}

func (g *GitStore) ExecTxMsg(msg string, fn func() error) error {
	g.mu.Lock()
	nested := g.txDepth > 0
	g.mu.Unlock()
	if nested {
		return fn()
	}
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	if err := g.pullForWrite(); err != nil {
		return err
	}
	g.mu.Lock()
	g.txDepth++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.txDepth--
		g.mu.Unlock()
	}()
	if err := fn(); err != nil {
		return err
	}
	if err := g.commit(msg); err != nil {
		return err
	}
	if err := g.push(); err != nil && !errors.Is(err, ErrNoRemote) {
		return err
	}
	return nil
}

func (g *GitStore) RotateSalt(saltB64 string) error {
	g.mu.Lock()
	inTx := g.txDepth > 0
	g.mu.Unlock()
	if !inTx {
		return errors.New("rotate salt must run inside a transaction")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	if len(salt) < 16 {
		return fmt.Errorf("salt must be at least 16 bytes")
	}
	g.mu.Lock()
	if g.meta == nil {
		err := g.metaErr
		g.mu.Unlock()
		if err != nil {
			return fmt.Errorf("vault metadata missing or invalid: %w", err)
		}
		return errors.New("vault metadata missing or invalid")
	}
	g.meta.SaltB64 = saltB64
	encoded := g.meta.Encode()
	g.mu.Unlock()
	if err := os.WriteFile(filepath.Join(g.repoDir, "psst.yaml"), encoded, 0o600); err != nil {
		return fmt.Errorf("write vault metadata: %w", err)
	}
	if _, err := g.git.Run("add", "psst.yaml"); err != nil {
		return fmt.Errorf("git add psst.yaml: %w", err)
	}
	g.markDirty()
	return nil
}

func (g *GitStore) SyncAcceptRotation() (*VaultMeta, error) {
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return nil, err
	}
	defer lock.Unlock()
	if _, err := g.git.Run("pull", "--rebase", "--autostash"); err != nil {
		g.git.Run("rebase", "--abort")
		msg := err.Error()
		if strings.Contains(msg, "CONFLICT") || strings.Contains(msg, "could not apply") || strings.Contains(msg, "Rebase") {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("pull failed: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(g.repoDir, "psst.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read vault metadata: %w", err)
	}
	newMeta, err := ParseVaultMeta(data)
	if err != nil {
		return nil, fmt.Errorf("invalid vault metadata: %w", err)
	}
	if g.opts.LoadPins != nil {
		if pin := g.opts.LoadPins(); pin != nil {
			if newMeta.SaltB64 == pin.SaltB64 {
				if err := CheckPinned(newMeta, pin); err != nil {
					return nil, fmt.Errorf("vault KDF parameters: %w", err)
				}
			} else {
				p, m := pin.Params, newMeta.Params
				if m.Time < p.Time || m.Memory < p.Memory || m.Threads < p.Threads {
					return nil, fmt.Errorf("rotation weakens KDF parameters: %w", ErrKDFWeakened)
				}
			}
		}
	}
	g.mu.Lock()
	g.meta = newMeta
	g.mu.Unlock()
	return newMeta, nil
}

func (g *GitStore) AheadOfUpstream() bool {
	out, err := g.git.Run("status", "-sb")
	if err != nil {
		return false
	}
	first := out
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		first = out[:i]
	}
	return strings.Contains(first, "[ahead")
}
```

(The old `ExecTx` body is replaced by the delegation shown; delete the duplicated logic. Imports: `encoding/base64` may be new to git.go.)

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/git.go internal/store/git_test.go
git commit -m "feat: ExecTxMsg, RotateSalt, SyncAcceptRotation and AheadOfUpstream"
```

---

### Task 2: `vault.Rotate` + `VerifyAllDecryptable`

**Files:**
- Modify: `internal/vault/vault.go`
- Test: `internal/vault/vault_test.go` (extend)

**Interfaces:**
- Produces:
  - `func (v *Vault) VerifyAllDecryptable() error` — pre-flight over store ciphertext, per-secret zeroing, fails naming the first offender.
  - `func (v *Vault) Rotate(newPassword string) (int, error)` — mints salt/key/AAD; `ExecTxMsg("psst: rotate", …)` with in-tx set re-derivation; `RotateSalt` last; zeroing of new-key material on failure; on success swaps `v.key`/`v.aad` and `SetUnlockedFingerprint(gs.FingerprintOfCurrent())`; non-GitStore → `rotate requires git storage`.

- [ ] **Step 1: Write failing tests**

Add to `internal/vault/vault_test.go`:

```go
func TestVaultRotate(t *testing.T) {
	remote := newBareRemoteVault(t)
	repo := filepath.Join(t.TempDir(), "repo")
	gs, err := store.NewGitStore(repo, store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatal(err)
	}
	if err := gs.InitSchema(); err != nil {
		t.Fatal(err)
	}
	v := vaultFromPassword(t, gs, "test-password")
	if err := v.SetSecret("API_KEY", []byte("secret123"), []string{"prod"}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret("DB_PASS", []byte("test-password"), nil); err != nil {
		t.Fatal(err)
	}
	oldSalt, _ := gs.GetMeta("kdf_salt")

	n, err := v.Rotate("new-password")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n != 2 {
		t.Fatalf("rotated = %d, want 2", n)
	}
	newSalt, _ := gs.GetMeta("kdf_salt")
	if newSalt == oldSalt || newSalt == "" {
		t.Fatalf("salt unchanged: %q", newSalt)
	}
	out, _ := store.NewGitRunner(repo).Run("log", "--format=%s", "-2")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 || lines[0] != "psst: rotate" {
		t.Fatalf("log = %q", out)
	}
	got, err := v.GetSecret("API_KEY")
	if err != nil || string(got.Value) != "secret123" || got.Tags[0] != "prod" {
		t.Fatalf("roundtrip = %q %v", got.Value, err)
	}
	if err := v.SetSecret("AFTER", []byte("x"), nil); err != nil {
		t.Fatalf("same-process write: %v", err)
	}
}

func TestVaultRotateOldKeyDies(t *testing.T) {
	remote := newBareRemoteVault(t)
	repo := filepath.Join(t.TempDir(), "repo")
	gs, _ := store.NewGitStore(repo, store.GitOptions{Remote: remote})
	if err := gs.InitSchema(); err != nil {
		t.Fatal(err)
	}
	v := vaultFromPassword(t, gs, "test-password")
	if err := v.SetSecret("API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Rotate("new-password"); err != nil {
		t.Fatal(err)
	}
	old := vaultFromPassword(t, gs, "test-password")
	if _, err := old.GetSecret("API_KEY"); err == nil {
		t.Fatal("old password must not decrypt after rotation")
	}
}

func TestVaultRotateIncludesInTxArrivals(t *testing.T) {
	remote := newBareRemoteVault(t)
	repo := filepath.Join(t.TempDir(), "repo")
	gs, _ := store.NewGitStore(repo, store.GitOptions{Remote: remote})
	if err := gs.InitSchema(); err != nil {
		t.Fatal(err)
	}
	v := vaultFromPassword(t, gs, "test-password")
	if err := v.SetSecret("API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatal(err)
	}
	other, _ := store.NewGitStore(filepath.Join(t.TempDir(), "repo2"), store.GitOptions{Remote: remote})
	ov := vaultFromPassword(t, other, "test-password")
	if err := ov.SetSecret("LATE", []byte("late-secret456"), nil); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyAllDecryptable(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Rotate("new-password"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	got, err := v.GetSecret("LATE")
	if err != nil || string(got.Value) != "late-secret456" {
		t.Fatalf("late arrival not rotated: %q %v", got.Value, err)
	}
}

func TestVaultRotateAbortsOnUndecryptable(t *testing.T) {
	g, _ := newGitVaultStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("BAD", []byte("garbage-not-base64!"), iv, nil); err != nil {
		t.Fatal(err)
	}
	v := vaultFromPassword(t, g, "test-password")
	if err := v.VerifyAllDecryptable(); err == nil {
		t.Fatal("pre-flight must fail on garbage")
	}
	if _, err := v.Rotate("new-password"); err == nil {
		t.Fatal("rotate must abort")
	}
	salt, _ := g.GetMeta("kdf_salt")
	if salt == "" {
		t.Fatal("salt lost")
	}
}

func TestVaultRotateEmptyVault(t *testing.T) {
	g, _ := newGitVaultStore(t)
	v := vaultFromPassword(t, g, "test-password")
	n, err := v.Rotate("new-password")
	if err != nil || n != 0 {
		t.Fatalf("empty rotate = %d %v", n, err)
	}
	if err := v.SetSecret("FIRST", []byte("x"), nil); err != nil {
		t.Fatalf("write after empty rotate: %v", err)
	}
}
```

Helpers (add once; `newGitVaultStore` = local-only `NewGitStore`+`InitSchema`; `vaultFromPassword` and `newBareRemoteVault` mirror the phase-1 patterns — check whether same-named helpers already exist in `vault_test.go`/`git_test.go` first and reuse):

```go
func newBareRemoteVault(t *testing.T) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return remote
}

func vaultFromPassword(t *testing.T, gs *store.GitStore, password string) *Vault {
	t.Helper()
	enc := crypto.NewAESGCM()
	v := New(enc, keyring.NewPasswordProvider(enc, false), gs)
	t.Setenv("PSST_PASSWORD", password)
	if err := v.Unlock(); err != nil {
		t.Fatalf("unlock %q: %v", password, err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}
```

Note `t.Setenv` inside a helper called multiple times per test re-sets the env — fine (sequential).

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/vault/ -run 'Rotate|VerifyAll' -v`
Expected: FAIL — `v.Rotate undefined`.

- [ ] **Step 3: Implement**

Add to `internal/vault/vault.go` (imports: `crypto/rand` already present; `bytes` not needed):

```go
func (v *Vault) VerifyAllDecryptable() error {
	all, err := v.store.GetAllSecrets()
	if err != nil {
		return fmt.Errorf("get secrets: %w", err)
	}
	for _, s := range all {
		plaintext, err := v.decrypt(s.EncryptedValue, s.IV)
		if err != nil {
			return fmt.Errorf("secret %s is undecryptable under the current key", s.Name)
		}
		for i := range plaintext {
			plaintext[i] = 0
		}
	}
	return nil
}

func (v *Vault) Rotate(newPassword string) (int, error) {
	if v.key == nil {
		return 0, errors.New("vault is locked")
	}
	gs, ok := v.store.(*store.GitStore)
	if !ok {
		return 0, errors.New("rotate requires git storage")
	}
	params := crypto.KDFParams{
		Time:    uint32(metaAtoi(v.store, "kdf_time")),
		Memory:  uint32(metaAtoi(v.store, "kdf_memory")),
		Threads: uint8(metaAtoi(v.store, "kdf_threads")),
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return 0, fmt.Errorf("generate salt: %w", err)
	}
	newSaltB64 := base64.StdEncoding.EncodeToString(salt)
	newKey, err := v.enc.DeriveKeyFromPassword(newPassword, salt, params)
	if err != nil {
		return 0, fmt.Errorf("derive key: %w", err)
	}
	newAAD := []byte("psst:v1:argon2id:" + newSaltB64)
	rotated := 0
	success := false
	defer func() {
		if !success {
			for i := range newKey {
				newKey[i] = 0
			}
		}
	}()
	err = gs.ExecTxMsg("psst: rotate", func() error {
		all, err := v.store.GetAllSecrets()
		if err != nil {
			return fmt.Errorf("get secrets: %w", err)
		}
		for _, s := range all {
			plaintext, derr := v.decrypt(s.EncryptedValue, s.IV)
			if derr != nil {
				return fmt.Errorf("secret %s is undecryptable under the current key", s.Name)
			}
			var ct, iv []byte
			ct, iv, derr = v.enc.EncryptWithAAD(plaintext, newKey, newAAD)
			for i := range plaintext {
				plaintext[i] = 0
			}
			if derr != nil {
				return fmt.Errorf("encrypt %s: %w", s.Name, derr)
			}
			if err := v.store.SetSecret(s.Name, ct, iv, s.Tags); err != nil {
				return fmt.Errorf("update %s: %w", s.Name, err)
			}
			rotated++
		}
		return gs.RotateSalt(newSaltB64)
	})
	if err != nil {
		return rotated, err
	}
	success = true
	v.key = newKey
	v.aad = newAAD
	gs.SetUnlockedFingerprint(gs.FingerprintOfCurrent())
	return rotated, nil
}
```

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "feat: vault key rotation with in-transaction re-encryption"
```

---

### Task 3: `psst rotate` command

**Files:**
- Create: `internal/cli/rotate.go`
- Test: `tests/rotate_test.go` (integration)

**Interfaces:**
- Consumes: `vault.Rotate`/`VerifyAllDecryptable`, `store.NewGitStore`, `OpenVaultStore`, `LoadVaultConfig`/`SaveVaultConfig`, `keyring.NewPasswordProvider(enc, true)`.
- Produces: cobra command `rotate` (flag `--stdin`); helper `readNewPassword(useStdin bool) (string, error)`.

- [ ] **Step 1: Write failing tests**

Create `tests/rotate_test.go`:

```go
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func (e *testEnv) runWithPassword(t *testing.T, password string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(e.binary, args...)
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD="+password, "HOME="+e.dir)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
	}
	return outBuf.String(), errBuf.String(), code
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func runRotateStdin(t *testing.T, e *testEnv, oldPassword, newPassword string) (string, int) {
	t.Helper()
	cmd := exec.Command(e.binary, "rotate", "--stdin")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD="+oldPassword, "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte(newPassword + "\n"))
		stdin.Close()
	}()
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors2(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
	}
	return outBuf.String() + errBuf.String(), code
}

func errors2(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func TestRotateEndToEnd(t *testing.T) {
	e := newTestEnv(t)
	if _, _, code := e.run("init", "--storage", "git"); code != 0 {
		t.Fatal("git init failed")
	}
	e.setSecret(t, "API_KEY", "secret123")

	out, code := runRotateStdin(t, e, "test-password", "new-password")
	if code != 0 {
		t.Fatalf("rotate failed: %s", out)
	}
	if !strings.Contains(out, "Rotated: 1 secrets re-encrypted") {
		t.Fatalf("summary: %s", out)
	}
	if _, _, code := e.runWithPassword(t, "test-password", "get", "API_KEY", "--storage", "git"); code != 1 {
		t.Fatal("old password must fail after rotation")
	}
	stdout, _, code := e.runWithPassword(t, "new-password", "get", "API_KEY", "--storage", "git")
	if code != 0 || !strings.Contains(stdout, "secret123") {
		t.Fatalf("new password get: %s %d", stdout, code)
	}
}

func TestRotateEmptyStdinAborts(t *testing.T) {
	e := newTestEnv(t)
	e.run("init", "--storage", "git")
	out, code := runRotateStdin(t, e, "test-password", "")
	if code != 1 || !strings.Contains(out, "empty") {
		t.Fatalf("empty stdin = %d %s", code, out)
	}
}

func TestRotateEmptyVault(t *testing.T) {
	e := newTestEnv(t)
	e.run("init", "--storage", "git")
	out, code := runRotateStdin(t, e, "test-password", "new-password")
	if code != 0 {
		t.Fatalf("empty vault rotate = %d %s", code, out)
	}
	if _, _, code := e.runWithPassword(t, "new-password", "set", "FIRST", "--stdin"); code != 0 {
		t.Fatalf("set after rotate: %d", code)
	}
}

func TestRotateRequiresGit(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	_, stderr, code := e.run("rotate", "--stdin")
	if code != 1 || !strings.Contains(stderr, "git storage") {
		t.Fatalf("sqlite rotate = %d %s", code, stderr)
	}
}

func TestRotateNoTTYNoStdin(t *testing.T) {
	e := newTestEnv(t)
	e.run("init", "--storage", "git")
	_, stderr, code := e.run("rotate")
	if code != 1 || !strings.Contains(stderr, "--stdin") {
		t.Fatalf("no tty = %d %s", code, stderr)
	}
}

func TestRotatePushFailureRecoveryHint(t *testing.T) {
	e := newTestEnv(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("bare: %v\n%s", err, out)
	}
	e.run("init", "--storage", "git", "--remote", remote)
	e.setSecret(t, "API_KEY", "secret123")
	st, _ := os.Stat(remote)
	if err := os.Chmod(remote, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(remote, st.Mode().Perm()) })
	out, code := runRotateStdin(t, e, "test-password", "new-password")
	if code != 1 || !strings.Contains(out, "psst sync") || !strings.Contains(out, "--discard-local") {
		t.Fatalf("push failure = %d %s", code, out)
	}
	if err := os.Chmod(remote, st.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
}
```

Note: `runRotateEmptyVault`'s wrong-old-password residual is implicitly covered — the unlock succeeds with any password on an empty vault. Collapse the duplicated exit-error helpers into ONE helper (`exitCode(err) int`) and use it in both runners — do not ship two copies.

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./tests/ -run TestRotate -v`
Expected: FAIL — unknown command `rotate`.

- [ ] **Step 3: Implement**

Create `internal/cli/rotate.go`:

```go
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

func readNewPassword(useStdin bool) (string, error) {
	if useStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read password: %w", err)
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return "", errors.New("empty password on stdin")
		}
		return pw, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no terminal available: pass the new password via --stdin")
	}
	fmt.Fprint(os.Stderr, "New password: ")
	b1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Fprint(os.Stderr, "Confirm: ")
	b2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(b1) != string(b2) {
		return "", errors.New("passwords do not match")
	}
	if len(b1) == 0 {
		return "", errors.New("empty password")
	}
	return string(b1), nil
}

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate vault key: new salt, all secrets re-encrypted in one commit",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		useStdin, _ := cmd.Flags().GetBool("stdin")

		envDir, err := vault.FindVaultDir(global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		storage, err := ResolveStorage(getStorageFlag(cmd), envDir)
		if err != nil {
			exitWithError(err.Error())
		}
		if storage != "git" {
			exitWithError("psst rotate requires git storage; run 'psst migrate storage --to git'")
		}
		if !statExists(filepath.Join(envDir, "repo", ".git")) {
			printNoVault(jsonOut, quiet)
			//nolint:mnd // exit code for missing vault
			os.Exit(3)
		}
		s, gs, err := OpenVaultStore(envDir, "git", "", false)
		if err != nil {
			exitWithError(fmt.Sprintf("open vault: %v", err))
		}
		if err := s.InitSchema(); err != nil {
			exitWithError(err.Error())
		}
		enc := crypto.NewAESGCM()
		v := vault.New(enc, keyring.NewPasswordProvider(enc, true), s)
		if err := v.Unlock(); err != nil {
			printAuthFailed(jsonOut, quiet)
			//nolint:mnd // exit code for auth failure
			os.Exit(5)
		}
		defer v.Close()

		metas, err := v.ListSecrets()
		if err != nil {
			exitWithError(err.Error())
		}
		if err := v.VerifyAllDecryptable(); err != nil {
			exitWithError("rotate aborted: " + err.Error())
		}
		newPassword, err := readNewPassword(useStdin)
		if err != nil {
			exitWithError(err.Error())
		}
		n, err := v.Rotate(newPassword)
		if err != nil {
			exitWithError(err.Error() + "; working tree may be dirty; run 'psst sync --discard-local' to reset to the remote (pre-rotation) state")
		}
		if err := repinVault(envDir, gs); err != nil {
			f.Warning("Re-pin failed: " + err.Error() + "; run 'psst sync --accept-rotation'")
		}
		msg := fmt.Sprintf("Rotated: %d secrets re-encrypted, new salt pinned", n)
		if len(metas) == 0 {
			msg += " (password not verified: vault is empty)"
		}
		f.Success(msg)
	},
}

func repinVault(envDir string, gs *store.GitStore) error {
	saltB64, err := gs.GetMeta("kdf_salt")
	if err != nil {
		return err
	}
	cfg, err := LoadVaultConfig(envDir)
	if err != nil {
		return err
	}
	cfg.PinSalt = saltB64
	tv, _ := gs.GetMeta("kdf_time")
	mv, _ := gs.GetMeta("kdf_memory")
	th, _ := gs.GetMeta("kdf_threads")
	cfg.PinKDF.Time = uint32(atoiDefault(tv))
	cfg.PinKDF.Memory = uint32(atoiDefault(mv))
	cfg.PinKDF.Threads = uint8(atoiDefault(th))
	return SaveVaultConfig(envDir, *cfg)
}

func atoiDefault(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rotateCmd.Flags().Bool("stdin", false, "Read the new password from stdin (one line)")
	rootCmd.AddCommand(rotateCmd)
}
```

(`printAuthFailed` and `printNoVault` already exist in root.go; note `printAuthFailed`'s keychain-specific text is acceptable — rotate is git-only, the env branch applies.)

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/rotate.go tests/rotate_test.go
git commit -m "feat: psst rotate command"
```

---

### Task 4: `psst sync --accept-rotation` + error formatting

**Files:**
- Modify: `internal/cli/sync.go`
- Modify: `internal/cli/root.go:147-153` (hint scoping + single prefix)
- Test: `tests/rotate_test.go` (extend)

**Interfaces:**
- Consumes: Task 1 `SyncAcceptRotation`/`AheadOfUpstream`/`HasUpstream`, Task 3 patterns.
- Produces: `--accept-rotation` branch in sync; the scoped `ErrSaltChanged` hint.

- [ ] **Step 1: Write failing tests**

Add to `tests/rotate_test.go` (uses the two-clone pattern from `tests/git_storage_test.go` — read it for the remote+clone helpers `newBareRemote`/`gitRun` style; here inline for the integration package):

```go
type twoClones struct {
	t      *testing.T
	remote string
	a, b   *testEnv
}

func newTwoClones(t *testing.T) *twoClones {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("bare: %v\n%s", err, out)
	}
	tc := &twoClones{t: t, remote: remote, a: newTestEnv(t), b: newTestEnv(t)}
	tc.a.run("init", "--storage", "git", "--remote", remote)
	tc.b.run("init", "--storage", "git", "--remote", remote)
	return tc
}

func (tc *twoClones) seedOn(b *testEnv, name, value string) {
	tc.t.Helper()
	cmd := exec.Command(tc.b.binary, "set", name, "--stdin")
	cmd.Dir = b.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+b.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte(value + "\n"))
		stdin.Close()
	}()
	cmd.Run()
}

func TestAcceptRotationFlow(t *testing.T) {
	tc := newTwoClones(t)
	tc.seedOn(tc.a, "API_KEY", "secret123")
	tc.b.run("sync")

	if out, code := runRotateStdin(t, tc.a, "test-password", "new-password"); code != 0 {
		t.Fatalf("rotate: %s", out)
	}
	_, stderr, code := tc.b.runWithPassword(t, "test-password", "list", "--storage", "git")
	if code != 1 || !strings.Contains(stderr, "accept-rotation") {
		t.Fatalf("unaccepted clone = %d %s", code, stderr)
	}
	_, out, code := runAccept(t, tc.b, "wrong-password")
	if code != 1 || !strings.Contains(out, "wrong password") {
		t.Fatalf("wrong accept = %d %s", code, out)
	}
	_, stderr, code = tc.b.runWithPassword(t, "test-password", "list", "--storage", "git")
	if code != 1 {
		t.Fatal("pin must be unchanged after failed accept")
	}
	out, code = runAccept(t, tc.b, "new-password")
	if code != 0 || !strings.Contains(out, "Rotation accepted") {
		t.Fatalf("accept = %d %s", code, out)
	}
	stdout, _, code := tc.b.runWithPassword(t, "new-password", "get", "API_KEY", "--storage", "git")
	if code != 0 || !strings.Contains(stdout, "secret123") {
		t.Fatalf("post-accept get: %s %d", stdout, code)
	}
	_, stderr, code = tc.b.runWithPassword(t, "new-password", "rollback", "API_KEY", "--to", "1", "--storage", "git")
	if code != 1 || !strings.Contains(stderr, "predates a KDF migration") {
		t.Fatalf("pre-rotation rollback must fail closed: %d %s", code, stderr)
	}
}

func runAccept(t *testing.T, e *testEnv, password string) (string, int) {
	t.Helper()
	cmd := exec.Command(e.binary, "sync", "--accept-rotation")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD="+password, "HOME="+e.dir)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return outBuf.String() + errBuf.String(), code
}

func TestAcceptRotationOfflineRefusal(t *testing.T) {
	tc := newTwoClones(t)
	tc.seedOn(tc.a, "API_KEY", "secret123")
	tc.b.run("sync")
	if out, code := runRotateStdin(t, tc.a, "test-password", "new-password"); code != 0 {
		t.Fatalf("rotate: %s", out)
	}
	remoteRO := chmodRemoteReadOnly(t, tc.remote)
	tc.seedOn(tc.b, "OFFLINE", "offline-secret789")
	_, out, code := runAccept(t, tc.b, "new-password")
	if code != 1 || !strings.Contains(out, "unpushed local commits") {
		t.Fatalf("offline accept = %d %s", code, out)
	}
	restoreRemotePerms(t, tc.remote, remoteRO)
}

func chmodRemoteReadOnly(t *testing.T, remote string) os.FileMode {
	t.Helper()
	st, err := os.Stat(remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(remote, 0o555); err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func restoreRemotePerms(t *testing.T, remote string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(remote, mode); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptRotationNoopAndFlags(t *testing.T) {
	tc := newTwoClones(t)
	tc.seedOn(tc.a, "API_KEY", "secret123")
	tc.b.run("sync")
	if out, code := runAccept(t, tc.b, "test-password"); code != 0 {
		t.Fatalf("noop accept = %d %s", code, out)
	}
	_, stderr, code := tc.b.run("sync", "--accept-rotation", "--discard-local")
	if code != 1 || !strings.Contains(stderr, "mutually exclusive") {
		t.Fatalf("flags = %d %s", code, stderr)
	}
}
```

(`runAccept` may reuse the `exitCode` helper collapsed in Task 3 instead of the inline assertion — keep ONE idiom.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./tests/ -run 'AcceptRotation' -v`
Expected: FAIL — unknown flag `--accept-rotation`.

- [ ] **Step 3: Implement**

`internal/cli/sync.go` — after the `--discard-local` block, add the branch (and mutual exclusion before it):

```go
		acceptRotation, _ := cmd.Flags().GetBool("accept-rotation")
		if acceptRotation && discardLocal {
			exitWithError("--accept-rotation and --discard-local are mutually exclusive")
		}
```

```go
		if acceptRotation {
			if !gs.HasUpstream() {
				f.Warning("Working locally, no remote configured")
				return
			}
			if gs.AheadOfUpstream() {
				exitWithError("cannot accept rotation with unpushed local commits; run 'psst sync' first to push them, or 'psst sync --discard-local' to drop them (reflog retains values), then retry")
			}
			meta, err := gs.SyncAcceptRotation()
			if err != nil {
				exitWithError(err.Error())
			}
			probeStore, err := store.NewGitStore(filepath.Join(envDir, "repo"), store.GitOptions{})
			if err != nil {
				exitWithError(fmt.Sprintf("open probe store: %v", err))
			}
			defer probeStore.Close()
			enc := crypto.NewAESGCM()
			pv := vault.New(enc, keyring.NewPasswordProvider(enc, true), probeStore)
			if err := pv.Unlock(); err != nil {
				exitWithError("Failed to unlock vault. Set PSST_PASSWORD to the new password or run in a terminal")
			}
			defer pv.Close()
			metas, err := pv.ListSecrets()
			if err != nil {
				exitWithError(err.Error())
			}
			if len(metas) > 0 {
				if _, err := pv.GetSecret(metas[0].Name); err != nil {
					exitWithError("wrong password or undecryptable secret " + metas[0].Name)
				}
			}
			cfg, err := LoadVaultConfig(envDir)
			if err != nil {
				exitWithError(err.Error())
			}
			cfg.PinSalt = meta.SaltB64
			cfg.PinKDF = meta.Params
			if err := SaveVaultConfig(envDir, *cfg); err != nil {
				exitWithError(err.Error())
			}
			if len(metas) == 0 {
				f.Success("Rotation accepted (vault is empty: password not verified)")
			} else {
				f.Success("Rotation accepted")
			}
			return
		}
```

Register the flag: `syncCmd.Flags().Bool("accept-rotation", false, "Accept a remote key rotation after verifying the new password")`. Add needed imports (`fmt`, `path/filepath`, `crypto`, `keyring`, `vault`, `store` as required — several already present).

`internal/cli/root.go` — replace the salt/weakened error handling in `getUnlockedVault` (lines ~147-153) with scoped, single-prefix messages:

```go
		if errors.Is(schemaErr, store.ErrSaltChanged) {
			exitWithError(schemaErr.Error() + "; run 'psst sync --accept-rotation' (or re-clone)")
		}
		if errors.Is(schemaErr, store.ErrKDFWeakened) {
			exitWithError(schemaErr.Error() + "; see rotation procedure in docs")
		}
```

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/sync.go internal/cli/root.go tests/rotate_test.go
git commit -m "feat: psst sync --accept-rotation with password probe"
```

---

### Task 5: serve self-heal test + documentation

**Files:**
- Test: `internal/server/server_test.go` (extend)
- Modify: `docs/rules/security.md`, `README.md`, `docs/ru/README.md`

**Interfaces:** Produces: documentation + one server regression test.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/server_test.go`:

```go
func TestServeSelfHealAfterRotation(t *testing.T) {
	remote := newBareRemote(t)
	repo := filepath.Join(t.TempDir(), "repo")
	gs, err := store.NewGitStore(repo, store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := gs.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	seed := vault.New(crypto.NewAESGCM(), &fixedPasswordProvider{password: "test-password"}, gs)
	if err := seed.Unlock(); err != nil {
		t.Fatalf("seed unlock: %v", err)
	}
	if err := seed.SetSecret("API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatalf("seed set: %v", err)
	}
	digest := sha256.Sum256([]byte(testToken))
	s := New(Config{
		Store: gs, Enc: crypto.NewAESGCM(),
		Host: "127.0.0.1", Port: "7788", TokenDigest: digest,
		UnlockTimeout: 30 * time.Minute, SessionTTL: 24 * time.Hour,
		Now: time.Now, Log: log.New(io.Discard, "", 0),
	})
	t.Cleanup(s.Close)
	h := s.Handler()
	ck := loginOK(t, h)
	if rec := unlockVault(t, h, ck, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock: %d", rec.Code)
	}

	other, err := store.NewGitStore(filepath.Join(t.TempDir(), "repo2"), store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("other: %v", err)
	}
	if err := other.Sync(); err != nil {
		t.Fatalf("other sync: %v", err)
	}
	rot := vault.New(crypto.NewAESGCM(), &fixedPasswordProvider{password: "test-password"}, other)
	if err := rot.Unlock(); err != nil {
		t.Fatalf("rot unlock: %v", err)
	}
	if _, err := rot.Rotate("new-password"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := gs.SyncAcceptRotation(); err != nil {
		t.Fatalf("accept on server host: %v", err)
	}

	rec := do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"value":"x"}`, ck)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "reunlock") {
		t.Fatalf("stale write = %d %s", rec.Code, rec.Body.String())
	}
	rec = unlockVault(t, h, ck, "new-password")
	if rec.Code != 200 {
		t.Fatalf("unlock after rotation = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/api/secrets/API_KEY/value", "", ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "secret123") {
		t.Fatalf("reveal after rotation = %d %s", rec.Code, rec.Body.String())
	}
}
```

(`rot.Rotate` needs the Task 2 signature; `newBareRemote` already exists in the server test file from phase 2.)

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -run TestServeSelfHeal -v` → verify it fails before wiring anything (it should already pass if Tasks 1-4 are complete — this test is a regression guard; if it passes immediately, that is correct, note it and commit).

- [ ] **Step 2: Documentation**

`docs/rules/security.md` — replace the manual-rotation sentence in the "Git Storage" section (the one describing creating a new vault + migrate) with:

```markdown
- Key rotation (`psst rotate`): new salt + re-encryption of every secret + updated
  `psst.yaml` as ONE commit; the rotating machine re-pins itself. Every other machine
  must adopt explicitly: `psst sync --accept-rotation` (password-verified probe before
  the pin moves) or a fresh clone. Unpushed local commits block acceptance (recovery:
  `psst sync` or `--discard-local`). Pre-rotation history stays fail-closed for rollback.
```

`README.md` + `docs/ru/README.md` — add a "Key rotation / Ротация ключа" section after the render section: the two commands with examples (`echo "new-pass" | psst rotate --stdin`, `psst sync --accept-rotation`), the acceptance flow (old password fails on other machines with the accept hint; wrong accept password never re-pins), the unpushed-commits refusal, and the abort recovery (`--discard-local`, upstream is pre-rotation).

- [ ] **Step 3: Run tests + commit**

Run: `make test` → PASS. Commit:

```bash
git add internal/server/server_test.go docs/rules/security.md README.md docs/ru/README.md
git commit -m "test: serve self-heal after rotation; docs: rotation procedure"
```

---

## Final verification (after all tasks)

- [ ] `make test` green; `go vet ./...` clean; gofmt clean.
- [ ] Manual smoke in the worktree: two clones; rotate on A (`--stdin`); on B: `psst list` fails with the hint; wrong accept fails; right accept succeeds; get works with the new password.
- [ ] Spec §6 checklist fully covered by Tasks 1-5 (weaker-params rejection is Task 1's store-level test; serve self-heal is Task 5).
- [ ] Final diff review by a fresh subagent, then `git merge --no-ff feat/rotate` into main under maintainer review.

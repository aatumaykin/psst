# Git Storage Backend (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement GitStore — an encrypted-files-in-git storage backend for psst with multi-machine sync, alongside `init --storage git`, `psst sync`, and `migrate kdf`/`migrate storage` commands.

**Architecture:** GitStore implements the existing 14-method `SecretStore` interface (frozen) in `internal/store/git.go`, driven by a hardened system-git executor with a process lock. The vault layer gains a password-only unlock branch (KDF params + AAD from store metadata), re-encrypting rollback, and batch support. CLI gains a storage factory (flag > config.yaml > autodetect) and new commands. Spec: `docs/superpowers/specs/2026-09-11-git-storage-webui-render-design.md`.

**Tech Stack:** Go 1.26, stdlib (`os/exec`, `syscall` flock, `encoding/base64`, `text/template` not needed), `golang.org/x/term` (already in go.mod), `gopkg.in/yaml.v3`? — NO: parse `psst.yaml` with a hand-rolled parser to avoid new deps (fixed key order, simple subset). Existing deps only: cobra, modernc.org/sqlite, zalando/go-keyring, x/term, x/crypto.

## Global Constraints

- Agent never sees secret values; values only in `vault.GetSecret → crypto.Decrypt → runner.Exec` pipeline and now the git file codec (`store` holds ciphertext only — never plaintext).
- No new dependencies (`go.mod` untouched).
- No comments in code (only `//nolint:` directives, matching existing style).
- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`.
- `make test` must pass after every task (`go test ./... -v`).
- Tests use fake values (`"secret123"`, `test-password`), stdlib `testing` only.
- File format: one file per secret, `base64(IV ‖ ciphertext)` at `secrets/[tag/]NAME.enc`; tags match `[a-z][a-z0-9-]*`; secret names match `validName` (`[A-Z][A-Z0-9_]*`, `internal/cli/set.go:14`).
- `psst.yaml` KDF defaults MUST equal compiled constants: time=3, memory=65536 (KiB), threads=4 (`internal/crypto/aesgcm.go:15-20`).
- Salt strictly immutable; KDF params only monotonic strengthening; `git://` remotes always rejected; `http://` requires `--allow-insecure-remote`.
- Git subcommand allowlist: `clone, init, config, fetch, pull, add, rm, mv, commit, push, log, show, status` (+ `rebase --abort`; + `reset --hard @{upstream}` ONLY inside `sync --discard-local`).
- All git invocations: `-c core.hooksPath=/dev/null`, `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<empty file>`, `GIT_ASKPASS`/`SSH_ASKPASS` unset.
- Error wrapping: `fmt.Errorf("context: %w", err)`. No `errors.Wrap`.
- Module path: `github.com/aatumaykin/psst`.

---

### Task 1: Crypto extensions — KDFParams, DeriveKeyFromPassword, AAD

**Files:**
- Modify: `internal/crypto/crypto.go` (extend interfaces)
- Create: `internal/crypto/params.go` (KDFParams)
- Modify: `internal/crypto/aesgcm.go` (implement methods)
- Test: `internal/crypto/aesgcm_test.go` (extend)

**Interfaces:**
- Consumes: existing `Encryptor`, `keyring.KeyDeriver` (`internal/keyring/keyring.go:7-11`).
- Produces:
  - `type KDFParams struct { Time uint32; Memory uint32; Threads uint8 }`
  - `func DefaultKDFParams() KDFParams`
  - `func (a *AESGCM) DeriveKeyFromPassword(password string, salt []byte, params KDFParams) ([]byte, error)`
  - `func (a *AESGCM) EncryptWithAAD(plaintext, key, aad []byte) (ciphertext, iv []byte, err error)`
  - `func (a *AESGCM) DecryptWithAAD(ciphertext, iv, key, aad []byte) ([]byte, error)`
  - `Encryptor` and `KeyDeriver` interfaces gain all three methods.

- [ ] **Step 1: Write failing tests**

Add to `internal/crypto/aesgcm_test.go`:

```go
func TestDeriveKeyFromPasswordNoPassthrough(t *testing.T) {
	a := NewAESGCM()
	salt := []byte("0123456789abcdef")

	key44 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	k1, err := a.DeriveKeyFromPassword(key44, salt, DefaultKDFParams())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(key44)
	if bytes.Equal(k1, decoded) {
		t.Fatal("base64-shaped password must not bypass Argon2")
	}
	if len(k1) != 32 {
		t.Fatalf("key length = %d, want 32", len(k1))
	}

	k2, _ := a.DeriveKeyFromPassword(key44, salt, DefaultKDFParams())
	if !bytes.Equal(k1, k2) {
		t.Fatal("derivation must be deterministic")
	}
	k3, _ := a.DeriveKeyFromPassword(key44, []byte("other-salt-16byt"), DefaultKDFParams())
	if bytes.Equal(k1, k3) {
		t.Fatal("different salt must yield different key")
	}
}

func TestDeriveKeyFromPasswordMatchesV2WithSalt(t *testing.T) {
	a := NewAESGCM()
	salt := []byte("0123456789abcdef")
	password := "test-password"
	legacy, err := a.KeyToBufferV2WithSalt(password, salt)
	if err != nil {
		t.Fatalf("legacy derive: %v", err)
	}
	typed, err := a.DeriveKeyFromPassword(password, salt, DefaultKDFParams())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !bytes.Equal(legacy, typed) {
		t.Fatal("DefaultKDFParams must equal compiled constants")
	}
}

func TestEncryptWithAAD(t *testing.T) {
	a := NewAESGCM()
	key := make([]byte, 32)
	rand.Read(key)
	aad := []byte("psst:v1:argon2id:c2FsdA==")

	ct, iv, err := a.EncryptWithAAD([]byte("secret123"), key, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := a.DecryptWithAAD(ct, iv, key, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "secret123" {
		t.Fatalf("plaintext = %q", pt)
	}
	if _, err = a.DecryptWithAAD(ct, iv, key, []byte("psst:v1:argon2id:other")); err == nil {
		t.Fatal("wrong AAD must fail authentication")
	}
	if _, err = a.DecryptWithAAD(ct, iv, key, nil); err == nil {
		t.Fatal("nil AAD must fail against AAD-bound ciphertext")
	}
}
```

Add `"crypto/rand"` and `"bytes"` imports if missing. Add `DefaultKDFParams` equivalence check uses constants directly.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/crypto/ -run 'DeriveKeyFromPassword|EncryptWithAAD' -v`
Expected: FAIL — `a.DeriveKeyFromPassword undefined`, `a.EncryptWithAAD undefined`.

- [ ] **Step 3: Implement**

Create `internal/crypto/params.go`:

```go
package crypto

type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

func DefaultKDFParams() KDFParams {
	return KDFParams{Time: argon2Iterations, Memory: argon2Memory, Threads: argon2Threads}
}
```

Extend `internal/crypto/crypto.go` interface:

```go
type Encryptor interface {
	Encrypt(plaintext []byte, key []byte) (ciphertext []byte, iv []byte, err error)
	Decrypt(ciphertext []byte, iv []byte, key []byte) ([]byte, error)
	EncryptWithAAD(plaintext, key, aad []byte) (ciphertext []byte, iv []byte, err error)
	DecryptWithAAD(ciphertext, iv, key, aad []byte) ([]byte, error)
	KeyToBuffer(key string) ([]byte, error)
	KeyToBufferV2(key string) ([]byte, error)
	KeyToBufferV2WithSalt(key string, salt []byte) ([]byte, error)
	DeriveKeyFromPassword(password string, salt []byte, params KDFParams) ([]byte, error)
	GenerateKey() ([]byte, error)
}
```

Extend `keyring.KeyDeriver` in `internal/keyring/keyring.go` the same way (add `DeriveKeyFromPassword`), since `AESGCM` satisfies both.

Add to `internal/crypto/aesgcm.go`:

```go
func (a *AESGCM) DeriveKeyFromPassword(password string, salt []byte, params KDFParams) ([]byte, error) {
	return argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, aesKeySize), nil
}

func (a *AESGCM) EncryptWithAAD(plaintext []byte, key []byte, aad []byte) ([]byte, iv []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create GCM: %w", err)
	}
	iv = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("generate IV: %w", err)
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, aad)
	return ciphertext, iv, nil
}

func (a *AESGCM) DecryptWithAAD(ciphertext []byte, iv []byte, key []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
```

Refactor `Encrypt`/`Decrypt` to delegate: `Encrypt` calls `EncryptWithAAD(plaintext, key, nil)`, `Decrypt` calls `DecryptWithAAD(ciphertext, iv, key, nil)` (delete their old bodies).

- [ ] **Step 4: Run tests**

Run: `go test ./internal/crypto/ ./internal/keyring/ -v`
Expected: PASS (all existing + new).

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/ internal/keyring/keyring.go
git commit -m "feat: KDFParams, DeriveKeyFromPassword and AAD methods in crypto"
```

---

### Task 2: Author field through the history stack

**Files:**
- Modify: `internal/store/store.go:21-29` (`HistoryEntry`)
- Modify: `internal/vault/types.go:22-26` (`SecretHistoryEntry`)
- Modify: `internal/vault/vault.go` (`GetHistory` mapping, ~line 232)
- Modify: `internal/output/output.go:27-31` (`HistoryItem`), HistoryEntries rendering
- Modify: `internal/cli/history.go:44-54` (`toHistoryItems`)
- Test: `internal/vault/vault_test.go` (extend)

**Interfaces:**
- Produces: `HistoryEntry.Author string`, `SecretHistoryEntry.Author string`, `output.HistoryItem.Author string` (JSON `author`, omitempty).
- SQLite leaves `Author` empty (zero value) — no sqlite.go changes needed.

- [ ] **Step 1: Write failing test**

In `internal/vault/vault_test.go` find the existing history test (pattern: testVault helper with `testKeyProvider`) and assert the new field maps through:

```go
func TestGetHistoryMapsAuthor(t *testing.T) {
	v := testVault(t)
	if err := v.SetSecret("API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := v.SetSecret("API_KEY", []byte("secret456"), nil); err != nil {
		t.Fatalf("set2: %v", err)
	}
	entries, err := v.GetHistory("API_KEY")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Author != "" {
		t.Fatalf("sqlite author = %q, want empty", entries[0].Author)
	}
	if entries[0].Version != 1 {
		t.Fatalf("version = %d, want 1", entries[0].Version)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vault/ -run TestGetHistoryMapsAuthor -v`
Expected: FAIL — `entries[0].Author undefined`.

- [ ] **Step 3: Implement**

- `internal/store/store.go` — add `Author string` to `HistoryEntry`.
- `internal/vault/types.go` — add `Author string` to `SecretHistoryEntry`.
- `internal/vault/vault.go` `GetHistory` mapping — add `Author: e.Author`.
- `internal/output/output.go` — `HistoryItem` gains `Author string \`json:"author,omitempty"\``; in `HistoryEntries` human output append ` by %s` when `Author != ""` (find the method around line 130; add conditional segment).
- `internal/cli/history.go` `toHistoryItems` — add `Author: e.Author`.

- [ ] **Step 4: Run tests**

Run: `go test ./... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/store.go internal/vault/ internal/output/output.go internal/cli/history.go
git commit -m "feat: Author field in secret history entries"
```

---

### Task 3: Password provider with TTY prompt

**Files:**
- Create: `internal/keyring/password.go`
- Create: `internal/keyring/password_test.go`
- Modify: `internal/keyring/keyring.go` (add `NewPasswordProvider`)

**Interfaces:**
- Consumes: `KeyProvider` interface, `x/term`.
- Produces:
  - `func NewPasswordProvider(allowPrompt bool) KeyProvider` — reads `PSST_PASSWORD`; if empty and `allowPrompt` and stdin is a TTY, prompts once (hidden input), caches for process lifetime.
  - `GetRawKey` returns the password string; `SetKey` returns `errors.New("password provider is read-only")`; `IsAvailable` = env set or promptable; `GenerateKey` delegates to deriver.

- [ ] **Step 1: Write failing test**

```go
package keyring

import (
	"os"
	"testing"
)

func TestPasswordProviderEnv(t *testing.T) {
	t.Setenv("PSST_PASSWORD", "test-password")
	p := NewPasswordProvider(nil, false)
	raw, err := p.GetRawKey("psst", "vault-key")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if raw != "test-password" {
		t.Fatalf("raw = %q", raw)
	}
	if !p.IsAvailable() {
		t.Fatal("available")
	}
	if err := p.SetKey("psst", "vault-key", []byte("x")); err == nil {
		t.Fatal("SetKey must fail")
	}
}

func TestPasswordProviderEmptyFails(t *testing.T) {
	t.Setenv("PSST_PASSWORD", "")
	p := NewPasswordProvider(nil, false)
	if _, err := p.GetRawKey("psst", "vault-key"); err == nil {
		t.Fatal("empty password must error")
	}
	if p.IsAvailable() {
		t.Fatal("not available without env or prompt")
	}
	if os.Getenv("PSST_PASSWORD") != "" {
		t.Fatal("env leaked")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keyring/ -run PasswordProvider -v`
Expected: FAIL — `NewPasswordProvider undefined`.

- [ ] **Step 3: Implement**

`internal/keyring/password.go`:

```go
package keyring

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"
)

type PasswordProvider struct {
	deriver     KeyDeriver
	allowPrompt bool
	once        sync.Once
	password    string
	promptErr   error
}

func NewPasswordProvider(deriver KeyDeriver, allowPrompt bool) *PasswordProvider {
	return &PasswordProvider{deriver: deriver, allowPrompt: allowPrompt}
}

func (p *PasswordProvider) resolve() (string, error) {
	if pw := os.Getenv("PSST_PASSWORD"); pw != "" {
		return pw, nil
	}
	if p.allowPrompt && term.IsTerminal(int(os.Stdin.Fd())) {
		p.once.Do(func() {
			fmt.Fprint(os.Stderr, "Enter vault password: ")
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				p.promptErr = fmt.Errorf("read password: %w", err)
				return
			}
			if len(b) == 0 {
				p.promptErr = errors.New("empty password")
				return
			}
			p.password = string(b)
		})
		return p.password, p.promptErr
	}
	return "", errors.New("PSST_PASSWORD not set and no terminal available")
}

func (p *PasswordProvider) GetRawKey(_, _ string) (string, error) {
	return p.resolve()
}

func (p *PasswordProvider) SetKey(_, _ string, _ []byte) error {
	return errors.New("password provider is read-only")
}

func (p *PasswordProvider) IsAvailable() bool {
	_, err := p.resolve()
	return err == nil
}

func (p *PasswordProvider) GenerateKey() ([]byte, error) {
	return p.deriver.GenerateKey()
}
```

`NewPasswordProvider` is registered in `internal/keyring/keyring.go` alongside `NewProvider` (no modification to `NewProvider` itself).

- [ ] **Step 4: Run tests**

Run: `go test ./internal/keyring/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/keyring/password.go internal/keyring/password_test.go internal/keyring/keyring.go
git commit -m "feat: password-only key provider with TTY prompt"
```

---

### Task 4: Vault metadata — psst.yaml model, validation, pins, file codec, path safety

**Files:**
- Create: `internal/store/vaultmeta.go`
- Create: `internal/store/vaultmeta_test.go`

**Interfaces:**
- Consumes: `crypto.KDFParams`, `crypto.DefaultKDFParams`.
- Produces:
  - `type VaultMeta struct { Version int; KDFAlgo string; Params crypto.KDFParams; SaltB64 string; Cipher string }`
  - `func NewVaultMeta(saltB64 string, params crypto.KDFParams) *VaultMeta`
  - `func ParseVaultMeta(data []byte) (*VaultMeta, error)` — strict validation: `version==1`, `cipher=="aes-256-gcm"`, `algo=="argon2id"`, `memory>=65536`, `time>=3`, `threads>=1`, salt base64 ≥16 bytes decoded.
  - `func (m *VaultMeta) Encode() []byte` — deterministic output, plain `key: value` lines (subset parser: no yaml dep).
  - `type Pin struct { SaltB64 string; Params crypto.KDFParams }`
  - `func CheckPinned(meta *VaultMeta, pin *Pin) error` — nil pin → nil; salt differ → `ErrSaltChanged`; params equal → nil; strictly stronger (no field decreased, ≥1 increased) → nil; else `ErrKDFWeakened`.
  - `var ErrSaltChanged = errors.New("vault salt changed")`, `var ErrKDFWeakened = errors.New("vault KDF parameters weakened or mixed")`
  - `func (m *VaultMeta) AAD() []byte` → `[]byte("psst:v1:" + m.KDFAlgo + ":" + m.SaltB64)`
  - `func (m *VaultMeta) Fingerprint() string` → `m.SaltB64 + "|" + strconv params`
  - Codec: `func EncodeSecretFile(ciphertext, iv []byte) []byte` → `base64.StdEncoding.EncodeToString(append(iv, ciphertext...))` newline-terminated; `func DecodeSecretFile(data []byte) (ciphertext, iv []byte, err error)` → inverse, errors on invalid base64 or IV shorter than 12 bytes.
  - Paths: `var ValidTag = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)`; `func SecretPath(secretsRoot, name string, tag string) (string, error)` — validates name via `^[A-Z][A-Z0-9_]*$` and tag via ValidTag (empty tag → root); returns `filepath.Join(root, dir, name+".enc")` built only from validated components.

- [ ] **Step 1: Write failing tests**

```go
package store

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/crypto"
)

func validMetaYAML() string {
	return "version: 1\n" +
		"kdf_algo: argon2id\n" +
		"kdf_time: 3\n" +
		"kdf_memory: 65536\n" +
		"kdf_threads: 4\n" +
		"salt: MDEyMzQ1Njc4OWFiY2RlZg==\n" +
		"cipher: aes-256-gcm\n"
}

func TestParseVaultMetaRoundTrip(t *testing.T) {
	m, err := ParseVaultMeta([]byte(validMetaYAML()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Params != crypto.DefaultKDFParams() {
		t.Fatalf("params = %+v", m.Params)
	}
	again, err := ParseVaultMeta(m.Encode())
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if again.Fingerprint() != m.Fingerprint() {
		t.Fatal("fingerprint unstable")
	}
}

func TestParseVaultMetaRejects(t *testing.T) {
	cases := map[string]string{
		"bad version":  strings.Replace(validMetaYAML(), "version: 1", "version: 2", 1),
		"bad cipher":   strings.Replace(validMetaYAML(), "aes-256-gcm", "aes-128", 1),
		"bad algo":     strings.Replace(validMetaYAML(), "argon2id", "scrypt", 1),
		"weak memory":  strings.Replace(validMetaYAML(), "kdf_memory: 65536", "kdf_memory: 1024", 1),
		"weak time":    strings.Replace(validMetaYAML(), "kdf_time: 3", "kdf_time: 1", 1),
		"short salt":   strings.Replace(validMetaYAML(), "MDEyMzQ1Njc4OWFiY2RlZg==", "c2hvcnQ=", 1),
		"missing salt": strings.Replace(validMetaYAML(), "salt: MDEyMzQ1Njc4OWFiY2RlZg==\n", "", 1),
	}
	for name, y := range cases {
		if _, err := ParseVaultMeta([]byte(y)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestCheckPinned(t *testing.T) {
	meta, _ := ParseVaultMeta([]byte(validMetaYAML()))
	if err := CheckPinned(meta, nil); err != nil {
		t.Fatalf("no pin: %v", err)
	}
	same := &Pin{SaltB64: meta.SaltB64, Params: meta.Params}
	if err := CheckPinned(meta, same); err != nil {
		t.Fatalf("same pin: %v", err)
	}
	stronger := &Pin{SaltB64: meta.SaltB64, Params: crypto.KDFParams{Time: 1, Memory: 65536, Threads: 4}}
	if err := CheckPinned(meta, stronger); err != nil {
		t.Fatalf("strengthening must be accepted: %v", err)
	}
	weaker := &Pin{SaltB64: meta.SaltB64, Params: crypto.KDFParams{Time: 4, Memory: 65536, Threads: 4}}
	if err := CheckPinned(meta, weaker); err == nil {
		t.Fatal("weakening must be rejected")
	}
	mixed := &Pin{SaltB64: meta.SaltB64, Params: crypto.KDFParams{Time: 1, Memory: 32768, Threads: 4}}
	if err := CheckPinned(meta, mixed); err == nil {
		t.Fatal("mixed change must be rejected")
	}
	otherSalt := &Pin{SaltB64: "AAAAAAAAAAAAAAAAAAAAAA==", Params: meta.Params}
	if err := CheckPinned(meta, otherSalt); err != ErrSaltChanged {
		t.Fatalf("salt change = %v, want ErrSaltChanged", err)
	}
}

func TestSecretFileCodec(t *testing.T) {
	iv := bytes.Repeat([]byte{7}, 12)
	ct := []byte("ciphertext-bytes")
	enc := EncodeSecretFile(ct, iv)
	if !bytes.HasSuffix(enc, []byte("\n")) {
		t.Fatal("newline terminated")
	}
	gotCT, gotIV, err := DecodeSecretFile(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(gotCT, ct) || !bytes.Equal(gotIV, iv) {
		t.Fatal("roundtrip mismatch")
	}
	if _, _, err := DecodeSecretFile([]byte("!!!notbase64!!!\n")); err == nil {
		t.Fatal("invalid base64 must error")
	}
	if _, _, err := DecodeSecretFile([]byte("c2hvcnQ=\n")); err == nil {
		t.Fatal("IV < 12 bytes must error")
	}
}

func TestSecretPath(t *testing.T) {
	p, err := SecretPath("/repo/secrets", "API_KEY", "")
	if err != nil || p != "/repo/secrets/API_KEY.enc" {
		t.Fatalf("root path = %q, %v", p, err)
	}
	p, err = SecretPath("/repo/secrets", "API_KEY", "prod")
	if err != nil || p != "/repo/secrets/prod/API_KEY.enc" {
		t.Fatalf("tag path = %q, %v", p, err)
	}
	if _, err := SecretPath("/repo/secrets", "api_key", ""); err == nil {
		t.Fatal("invalid name must error")
	}
	if _, err := SecretPath("/repo/secrets", "API_KEY", "../evil"); err == nil {
		t.Fatal("invalid tag must error")
	}
	if _, err := SecretPath("/repo/secrets", "API_KEY", "Prod"); err == nil {
		t.Fatal("uppercase tag must error")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -run 'VaultMeta|CheckPinned|SecretFile|SecretPath' -v`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Implement**

`internal/store/vaultmeta.go` — implement exactly the Produces list: strict line parser (split on `: `, reject unknown keys, reject duplicates), `Encode` writes the 7 fixed lines. Constants: `minKDFMemory = 65536`, `minKDFTime = 3`, `minKDFThreads = 1`, `ivSize = 12`. Note `minKDFTime = 3` equals `crypto.DefaultKDFParams().Time` — import crypto for the type only, keep numeric minimums local.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/store/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/vaultmeta.go internal/store/vaultmeta_test.go
git commit -m "feat: vault metadata model, pin policy, secret file codec and path safety"
```

---

### Task 5: Hardened git executor and repo lock

**Files:**
- Create: `internal/store/gitexec.go`
- Create: `internal/store/gitexec_test.go`

**Interfaces:**
- Produces:
  - `type GitRunner struct { dir string }`, `func NewGitRunner(dir string) *GitRunner`
  - `func (g *GitRunner) Run(args ...string) (stdout string, err error)` — executes `git` in `g.dir` with hardened env (Global Constraints list); enforces allowlist on `args[0]` (set: clone, init, config, fetch, pull, add, rm, mv, commit, push, log, show, status, rebase, reset); for `reset` requires `args[1] == "--hard"` and a `discardOK bool` receiver flag set only by `DiscardLocal` (implement as separate method `RunResetHardUpstream()` that bypasses the generic gate explicitly); for `rebase` requires `args[1] == "--abort"`. Error includes trimmed stderr.
  - `func (g *GitRunner) RunOK(args ...string) bool` — true when exit 0.
  - `type RepoLock struct{ path string; f *os.File }`, `func LockRepo(repoDir string) (*RepoLock, error)` — `flock(LOCK_EX)` with 10s deadline via polling loop on `syscall.Flock` non-blocking + 50ms sleeps; error "repo is locked by another psst process" on timeout; `func (l *RepoLock) Unlock() error` — flock LOCK_UN + close.

- [ ] **Step 1: Write failing test**

```go
package store

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func newBareRemote(t *testing.T) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return remote
}

func TestGitRunnerAllowlist(t *testing.T) {
	dir := t.TempDir()
	g := NewGitRunner(dir)
	if _, err := g.Run("status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	if _, err := g.Run("clean", "-fd"); err == nil {
		t.Fatal("clean must be rejected")
	}
	if _, err := g.Run("reset", "--hard", "HEAD"); err == nil {
		t.Fatal("generic reset must be rejected")
	}
	if _, err := g.Run("rebase", "--continue"); err == nil {
		t.Fatal("rebase --continue must be rejected")
	}
}

func TestGitRunnerEnv(t *testing.T) {
	dir := t.TempDir()
	g := NewGitRunner(dir)
	out, err := g.Run("config", "--get", "core.hooksPath")
	if err != nil {
		t.Fatalf("config get: %v", err)
	}
	if strings.TrimSpace(out) != "/dev/null" {
		t.Fatalf("hooksPath not enforced: %q", out)
	}
}

func TestRepoLockExclusive(t *testing.T) {
	dir := t.TempDir()
	l1, err := LockRepo(dir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := LockRepo(dir); err == nil {
		t.Fatal("second lock must time out")
	}
	if err := l1.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	l2, err := LockRepo(dir)
	if err != nil {
		t.Fatalf("relock after unlock: %v", err)
	}
	l2.Unlock()
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -run 'GitRunner|RepoLock' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement**

`internal/store/gitexec.go`: allowlisted subcommands as `map[string]bool`; env construction: copy `os.Environ()` filtering `GIT_`-prefixed vars, then set `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<repoDir>/.git/psst-empty-config` (create empty file with 0600 at lock time), unset `GIT_ASKPASS`, `SSH_ASKPASS`. All args prefixed `-c core.hooksPath=/dev/null`. `LockRepo` writes lock at `repoDir/.psst.lock` (parent must exist). Use `golang.org/x/sys/unix`? No — `syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)` (stdlib, matches linux/darwin).

- [ ] **Step 4: Run tests**

Run: `go test ./internal/store/ -run 'GitRunner|RepoLock' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/gitexec.go internal/store/gitexec_test.go
git commit -m "feat: hardened git executor with subcommand allowlist and repo lock"
```

---

### Task 6: GitStore — local CRUD, metadata, walk, reentrant ExecTx

**Files:**
- Create: `internal/store/git.go`
- Create: `internal/store/git_test.go`
- Modify: `internal/vault/vault.go` (`FindVaultPath` → `FindVaultDir`, sqlite path helper)

**Interfaces:**
- Consumes: `VaultMeta`/codec/`SecretPath` (Task 4), `GitRunner`/`RepoLock` (Task 5).
- Produces:
  - `type GitOptions struct { Remote string; AllowInsecureRemote bool; LoadPins func() *Pin; SavePins func(Pin) error }`
  - `func NewGitStore(repoDir string, opts GitOptions) (*GitStore, error)`
  - `func (g *GitStore) InitSchema() error` — idempotent, non-destructive (spec §1.2): valid repo+psst.yaml → no-op; repo exists, psst.yaml missing/invalid → error "vault metadata missing or invalid; refusing to regenerate (salt would invalidate all secrets)"; no repo dir → `git init` (clone handled by `InitGitVault`, Task 10) + mint salt + write psst.yaml + initial commit + set identity + save pins. No remote push here.
  - All 14 `SecretStore` methods. SetSecret derives path from `tags` (len>1 → error "git vault supports a single tag"), stages `git add <path>`, removes other copies of `NAME.enc` found via walk (`git rm`), commits when `txDepth == 0` with message `psst: set <NAME>` (messages: `set`, `rm`, `tag`, `untag`, `rollback`, `migrate`, `init`). `ExecTx` reentrant per spec §1.2.
  - `func (g *GitStore) SetUnlockedFingerprint(fp string)` + `var ErrRemoteMetaChanged = errors.New("vault parameters changed remotely; re-run the command")` (Task 7 uses it).
  - `func (g *GitStore) SyncPullRead() (warnUnpushed bool, err error)` — `pull --ff-only`; classify: no remote → (false, nil); network fail → (false, nil); diverged → (true, nil); used by GetSecret/GetAllSecrets/ListSecrets/GetHistory: on `warnUnpushed` print `psst: warning: local clone has unpushed changes; run psst sync` to stderr.
  - vault: `func FindVaultDir(global bool, env string) (string, error)` (old logic minus `vault.db` suffix); `func SQLitePath(dir string) string { return filepath.Join(dir, "vault.db") }`; keep `FindVaultPath` as wrapper calling both (existing callers unaffected).

- [ ] **Step 1: Write failing tests**

```go
package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aatumaykin/psst/internal/crypto"
)

func newGitStore(t *testing.T) (*GitStore, string) {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	g, err := NewGitStore(repo, GitOptions{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := g.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	return g, repo
}

func TestGitStoreCRUD(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("API_KEY", []byte("ct1"), iv, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := g.SetSecret("DB_PASS", []byte("ct2"), iv, []string{"prod"}); err != nil {
		t.Fatalf("set tagged: %v", err)
	}
	sec, err := g.GetSecret("DB_PASS")
	if err != nil || sec == nil {
		t.Fatalf("get: %v %v", sec, err)
	}
	if len(sec.Tags) != 1 || sec.Tags[0] != "prod" {
		t.Fatalf("tags = %v", sec.Tags)
	}
	if p := filepath.Join("secrets", "prod", "DB_PASS.enc"); sec.Name != "DB_PASS" || !hasFile(t, g, p) {
		t.Fatalf("file layout wrong: %s", sec.Name)
	}
	all, err := g.GetAllSecrets()
	if err != nil || len(all) != 2 {
		t.Fatalf("all = %v %v", all, err)
	}
	metas, err := g.ListSecrets()
	if err != nil || len(metas) != 2 {
		t.Fatalf("list = %v %v", metas, err)
	}
	if err := g.DeleteSecret("API_KEY"); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if sec, _ = g.GetSecret("API_KEY"); sec != nil {
		t.Fatal("deleted secret must be gone")
	}
}

func hasFile(t *testing.T, g *GitStore, rel string) bool {
	t.Helper()
	g2 := g
	_ = g2
	_, err := os.Stat(filepath.Join(g.repoDir, rel))
	return err == nil
}

func TestGitStoreMultiTagRejected(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, []string{"a", "b"}); err == nil {
		t.Fatal("multi-tag must fail closed")
	}
}

func TestGitStoreTagReplaceMovesFile(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, []string{"prod"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := g.SetSecret("KEY", []byte("ct"), iv, []string{"test"}); err != nil {
		t.Fatalf("retag: %v", err)
	}
	if _, err := os.Stat(filepath.Join(g.repoDir, "secrets", "prod", "KEY.enc")); !os.IsNotExist(err) {
		t.Fatal("old tag dir copy must be removed")
	}
	if _, err := os.Stat(filepath.Join(g.repoDir, "secrets", "test", "KEY.enc")); err != nil {
		t.Fatalf("new path: %v", err)
	}
}

func TestGitStoreExecTxBatch(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	err := g.ExecTx(func() error {
		for _, n := range []string{"A1", "B2", "C3"} {
			if err := g.SetSecret(n, []byte("ct"), iv, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	out, _ := NewGitRunner(g.repoDir).Run("log", "--oneline")
	if commits := countLines(out); commits != 2 {
		t.Fatalf("commits = %d, want 2 (init + one batch)", commits)
	}
}

func TestGitStoreMeta(t *testing.T) {
	g, _ := newGitStore(t)
	v, err := g.GetMeta("kdf_version")
	if err != nil || v != "2" {
		t.Fatalf("kdf_version = %q %v", v, err)
	}
	salt, _ := g.GetMeta("kdf_salt")
	if salt == "" {
		t.Fatal("salt exposed")
	}
	if aad, _ := g.GetMeta("vault_aad"); aad == "" {
		t.Fatal("aad exposed")
	}
	if tv, _ := g.GetMeta("kdf_time"); tv != "3" {
		t.Fatalf("kdf_time = %q", tv)
	}
	if _, err := g.GetMeta("nope"); err != nil {
		t.Fatalf("unknown key must return empty: %v", err)
	}
}

func TestGitStoreInitSchemaNonDestructive(t *testing.T) {
	g, repo := newGitStore(t)
	if err := g.InitSchema(); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "psst.yaml"), []byte("version: 9\n"), 0600); err != nil {
		t.Fatal(err)
	}
	g2, err := NewGitStore(repo, GitOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := g2.InitSchema(); err == nil {
		t.Fatal("corrupted psst.yaml must be a hard error")
	}
}

func TestGitStoreWalkIgnoresForeignPaths(t *testing.T) {
	g, repo := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, []string{"prod"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "secrets", "BadTag"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "secrets", "BadTag", "X.enc"), []byte("junk\n"), 0600); err != nil {
		t.Fatal(err)
	}
	metas, err := g.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 1 || metas[0].Name != "KEY" {
		t.Fatalf("walk must ignore foreign entries: %v", metas)
	}
}

func countLines(s string) int {
	n := 0
	for _, l := range splitLines(s) {
		if l != "" {
			n++
		}
	}
	return n
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

var _ = crypto.DefaultKDFParams
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -run GitStore -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement**

`internal/store/git.go` structure:

```go
package store

type GitStore struct {
	mu        sync.Mutex
	repoDir   string
	opts      GitOptions
	git       *GitRunner
	meta      *VaultMeta
	txDepth   int
	dirty     bool
	unlockedFP string
}

func NewGitStore(repoDir string, opts GitOptions) (*GitStore, error) {
	g := &GitStore{repoDir: repoDir, opts: opts, git: NewGitRunner(repoDir)}
	if metaPathExists(repoDir) {
		data, err := os.ReadFile(metaPath(repoDir))
		if err != nil {
			return nil, fmt.Errorf("read vault metadata: %w", err)
		}
		m, err := ParseVaultMeta(data)
		if err != nil {
			return nil, fmt.Errorf("invalid vault metadata: %w", err)
		}
		if pin := opts.LoadPins(); pin != nil {
			if err := CheckPinned(m, pin); err != nil {
				return nil, fmt.Errorf("vault metadata changed since last open: %w", err)
			}
		}
		g.meta = m
	}
	return g, nil
}
```

Key internals (write fully in implementation):
- `metaPath(dir) = filepath.Join(dir, "psst.yaml")`; `secretsRoot(dir) = filepath.Join(dir, "secrets")`.
- `InitSchema`: if `g.meta != nil` → verify repo dir exists (`.git` present) → no-op. If repoDir exists without valid psst.yaml → the hard error (message above). Else: `LockRepo`; `git init`; `git config user.name psst/<hostname>` / `user.email psst@<hostname>`; mint salt `crypto.RandSalt(16)`→ use `crypto/rand` locally: `salt := make([]byte, 16); rand.Read(salt)`; `g.meta = NewVaultMeta(base64, crypto.DefaultKDFParams())`; write file 0600; `git add psst.yaml`; commit `psst: init`; `SavePins`; `Unlock`.
- `mutate(msg string, op func() error) error`: lock repo (`LockRepo`/defer `Unlock`), `g.mu.Lock`; if `txDepth > 0` → run op (sets `dirty`), return. Else `pullForWrite()` (Task 7 stub returning nil in this task), `txDepth++`, run op, `txDepth--`, if dirty → `commit(msg)`, `push()`.
- `SetSecret(name string, encValue, iv []byte, tags []string)`: tag := ""; if len(tags) == 1 → tags[0]; if len(tags) > 1 → error; `path, err := SecretPath(secretsRoot(g.repoDir), name, tag)`; `os.MkdirAll(filepath.Dir(path), 0700)`; write `EncodeSecretFile(encValue, iv)` 0600; remove other copies: `for other := range g.locate(name)` where `locate` scans each valid tag dir + root for `name+".enc"` — `os.Remove` others; stage `git add <relpath>`; mark dirty. Wrap in `mutate("psst: set "+name, ...)`.
- `GetSecret/GetAllSecrets/ListSecrets`: `SyncPullRead()` (Task 7; stub no-op here) → walk/decode; `ListSecrets` uses `filepath.WalkDir` restricted to shape check via `SecretPath`-style validation (reuse `ValidTag` + name regex); `CreatedAt/UpdatedAt`: `git log` per file (Task 7; zero times acceptable in this task, refined in Task 7 — set both to `time.Time{}` now).
- `GetMeta(key)`: switch on `kdf_version`→"2", `kdf_salt`→`meta.SaltB64`, `kdf_time/memory/threads`→strconv of params, `vault_aad`→`string(meta.AAD())`, `storage`→"git"; default "".
- `SetMeta(key, value)`: honor only `kdf_time/kdf_memory/kdf_threads` (update `meta`, rewrite psst.yaml, stage) — else no-op. Wrapped in `mutate("psst: migrate", ...)`.
- `DeleteSecret`: locate file → `git rm -f <rel>` → `mutate("psst: rm "+name)`.
- `DeleteHistory/AddHistory/PruneHistory`: `return nil`. `Close`: `return nil`.
- `ExecTx(fn)`: `g.mu.Lock()`; if `txDepth > 0` → `g.mu.Unlock(); return fn()`; else lock repo, `pullForWrite()`, `txDepth++`, `fn()`, `txDepth--`, commit+push if dirty, unlock repo, `g.mu.Unlock()`.

vault.go: `FindVaultDir` + `SQLitePath` + `FindVaultPath` wrapper.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/store/ ./internal/vault/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/git.go internal/store/git_test.go internal/vault/vault.go
git commit -m "feat: GitStore local CRUD, metadata, walk and reentrant ExecTx"
```

---

### Task 7: GitStore — sync transport, history, post-pull metadata check

**Files:**
- Modify: `internal/store/git.go`
- Modify: `internal/store/git_test.go` (extend)

**Interfaces:**
- Consumes: Task 6 internals (`mutate`, `meta`, `git`).
- Produces (internal to store, plus these public):
  - `func (g *GitStore) Sync() error` — lock, `pull --rebase --autostash`; on conflict: `git rebase --abort`, error "key changed remotely; re-set the value or run `psst sync --discard-local`"; then fingerprint check; then `push`; no-remote → warning via returned sentinel `ErrNoRemote` (caller prints).
  - `func (g *GitStore) DiscardLocal() error` — lock, `RunResetHardUpstream()` (`reset --hard @{upstream}`), `ErrNoRemote` if no upstream.
  - `var ErrNoRemote = errors.New("no remote configured")`
  - `GetHistory(name)` per spec §1.2: `git log --follow --format=%H%x1f%cI%x1f%an --name-only -- <path>`; drop first entry (HEAD/current); load blob via `git show <rev>:<path>`; `Version = total - i` (oldest-based ordinal); DESC order (as parsed, newest first); `ID: 0`; `ArchivedAt` = commit time parsed `time.RFC3339`; `Author` from `%an`.
  - `pullForWrite()` internal: `pull --rebase --autostash` + conflict abort + fingerprint check + `push` deferred to commit step. Reads after pull: re-read psst.yaml → if `Fingerprint() != unlockedFP` (when `unlockedFP != ""`) → `ErrRemoteMetaChanged`.
  - `SyncPullRead()` implementation: no upstream → nil; run `pull --ff-only`; exit 0 → fingerprint check → nil; stderr contains "divergent"/non-fast-forward → `warnUnpushed=true` + fingerprint check via `pull` error path re-read; network errors (exit code 128 with connection text) → nil.
  - `SetUnlockedFingerprint(fp string)` stores; `FingerprintOfCurrent()` returns current meta fingerprint.
  - `ListSecrets/GetSecret` dates: `UpdatedAt` = newest commit time for file (`git log -1 --format=%cI -- path`), `CreatedAt` = `git log --diff-filter=A --format=%cI -- path` (fallback to UpdatedAt when rename-only history).

- [ ] **Step 1: Write failing tests**

```go
func newBareRemote(t *testing.T) string { ... } // from Task 5

func newClonedStore(t *testing.T, remote string) *GitStore {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	g, err := NewGitStore(repo, GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := g.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := g.pushAll(); err != nil {
		t.Fatalf("push: %v", err)
	}
	return g
}

func TestGitStoreSyncRoundTrip(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newClonedStore(t, remote)
	iv := make([]byte, 12)
	if err := g1.SetSecret("KEY", []byte("ct"), iv, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	g2, err := NewGitStore(filepath.Join(t.TempDir(), "repo2"), GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("clone-open: %v", err)
	}
	if err := g2.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	sec, err := g2.GetSecret("KEY")
	if err != nil || sec == nil {
		t.Fatalf("get after sync: %v", err)
	}
}

func TestGitStoreConflictFailsClosed(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newClonedStore(t, remote)
	g2 := newClonedStore(t, remote)
	iv := make([]byte, 12)
	_ = g1.SetSecret("KEY", []byte("one"), iv, nil)
	_ = g2.Sync()
	_ = g2.SetSecret("KEY", []byte("two"), iv, nil)
	err := g1.SetSecret("KEY", []byte("three"), iv, nil)
	if err == nil {
		t.Fatal("same-key race must fail closed")
	}
}

func TestGitStoreDifferentKeysRebase(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newClonedStore(t, remote)
	g2 := newClonedStore(t, remote)
	iv := make([]byte, 12)
	if err := g1.SetSecret("A1", []byte("x"), iv, nil); err != nil {
		t.Fatalf("set A1: %v", err)
	}
	if err := g2.SetSecret("B2", []byte("y"), iv, nil); err != nil {
		t.Fatalf("set B2 must succeed after rebase: %v", err)
	}
	g3, _ := NewGitStore(filepath.Join(t.TempDir(), "r3"), GitOptions{Remote: remote})
	_ = g3.Sync()
	if _, err := g3.GetSecret("A1"); err != nil {
		t.Fatalf("A1 lost: %v", err)
	}
	if _, err := g3.GetSecret("B2"); err != nil {
		t.Fatalf("B2 lost: %v", err)
	}
}

func TestGitStoreDiscardLocalRecovers(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newClonedStore(t, remote)
	g2 := newClonedStore(t, remote)
	iv := make([]byte, 12)
	_ = g2.SetSecret("KEY", []byte("remote-wins"), iv, nil)
	_ = g1.SetSecret("KEY", []byte("local-loses"), iv, nil)
	if err := g1.SetSecret("OTHER", []byte("z"), iv, nil); err == nil {
		t.Fatal("expected conflict deadlock")
	}
	if err := g1.DiscardLocal(); err != nil {
		t.Fatalf("discard: %v", err)
	}
	if err := g1.SetSecret("OTHER", []byte("z"), iv, nil); err != nil {
		t.Fatalf("recovered: %v", err)
	}
}

func TestGitStoreStaleKeyAborts(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newClonedStore(t, remote)
	iv := make([]byte, 12)
	_ = g1.SetSecret("KEY", []byte("ct"), iv, nil)
	g1.SetUnlockedFingerprint(g1.FingerprintOfCurrent())

	g2 := newClonedStore(t, remote)
	_ = g2.Sync()
	newParams := g2.meta.Params
	newParams.Time = 4
	g2.meta.Params = newParams
	if err := g2.writeMeta(); err != nil {
		t.Fatal(err)
	}
	if err := g2.commit("psst: migrate"); err != nil {
		t.Fatal(err)
	}
	_ = g2.pushAll()

	err := g1.SetSecret("KEY2", []byte("ct"), iv, nil)
	if !errors.Is(err, ErrRemoteMetaChanged) {
		t.Fatalf("stale write = %v, want ErrRemoteMetaChanged", err)
	}
}

func TestGitStoreGetHistory(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	_ = g.SetSecret("KEY", []byte("v1"), iv, nil)
	_ = g.SetSecret("KEY", []byte("v2"), iv, nil)
	_ = g.SetSecret("KEY", []byte("v3"), iv, nil)
	h, err := g.GetHistory("KEY")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(h) != 2 {
		t.Fatalf("entries = %d, want 2 (HEAD excluded)", len(h))
	}
	if h[0].Version != 2 || h[1].Version != 1 {
		t.Fatalf("versions = %d,%d want 2,1 (DESC, oldest-based)", h[0].Version, h[1].Version)
	}
	if !bytes.Equal(h[1].EncryptedValue, []byte("v1")) {
		t.Fatal("oldest entry must carry v1 ciphertext")
	}
	if h[0].Author == "" {
		t.Fatal("author populated")
	}
}

func TestGitStoreOfflineRead(t *testing.T) {
	g := newClonedStore(t, newBareRemote(t))
	iv := make([]byte, 12)
	_ = g.SetSecret("KEY", []byte("ct"), iv, nil)
	g.opts.Remote = "/nonexistent/remote.git"
	if _, err := g.GetSecret("KEY"); err != nil {
		t.Fatalf("offline read must work: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -run 'GitStoreSync|GitStoreConflict|GitStoreDifferent|GitStoreDiscard|GitStoreStale|GitStoreGetHistory|GitStoreOffline' -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

Complete in `git.go`:
- `hasUpstream()`: `git rev-parse --abbrev-ref @{upstream}` exit code.
- `pushAll()/push()`: `git push -u origin HEAD` when `opts.Remote != ""` else `ErrNoRemote` wrapped as warning sentinel; on push failure return error "push failed; change is in the local clone, run `psst sync` later: %w".
- `pullForWrite()`: skip when no upstream; `git pull --rebase --autostash`; nonzero → `git rebase --abort` → error "key changed remotely; re-set the value or run `psst sync --discard-local`". Then `reloadMetaAndCheck()`.
- `reloadMetaAndCheck()`: re-read psst.yaml from disk → Parse → if `g.unlockedFP != "" && fp != g.unlockedFP` → `ErrRemoteMetaChanged`; also run `CheckPinned` against `opts.LoadPins()` (salt changed → ErrSaltChanged surfaced).
- `SyncPullRead()`: per Produces; network classification: exit error AND stderr containing one of `Could not resolve`, `Connection`, `Network is unreachable`, `timed out` → nil (silent local).
- `commit(msg)`: `git add -u` is FORBIDDEN — stage explicit paths only (mutate ops already staged); `git commit -m msg`; `dirty = false`.
- `GetHistory`: parse `--name-only` pairs (commit header lines with `%x1f` fields, then indented path line); for each non-HEAD entry `git show <rev>:<path>` → `DecodeSecretFile`.
- Dates: helper `fileTimes(rel)` with two `git log` calls.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/store/ -v`
Expected: PASS (all GitStore tests).

- [ ] **Step 5: Commit**

```bash
git add internal/store/git.go internal/store/git_test.go
git commit -m "feat: GitStore sync protocol, history and post-pull metadata check"
```

---

### Task 8: Vault integration — git unlock branch, AAD, RetagSecret, Batch, re-encrypting rollback, params-aware MigrateKDF

**Files:**
- Modify: `internal/vault/vault.go`
- Modify: `internal/vault/vault_test.go` (extend)

**Interfaces:**
- Consumes: Tasks 1–7 products.
- Produces:
  - `Vault` fields `aad []byte`; `Unlock()` extension: read `kdf_time` via `GetMeta` — if non-empty: params from `kdf_time/kdf_memory/kdf_threads`, salt from `kdf_salt`, `key = enc.DeriveKeyFromPassword(rawKey, salt, params)`; `aad = GetMeta("vault_aad")` decoded to bytes (empty → nil); if store is `*store.GitStore` → `gs.SetUnlockedFingerprint(salt + "|" + params)`. SQLite path unchanged (params meta absent).
  - `func (v *Vault) RetagSecret(name string, tags []string) error` — read stored secret, `SetSecret(name, sec.EncryptedValue, sec.IV, tags)` inside `ExecTx`.
  - `func (v *Vault) Batch(fn func() error) error` — `v.store.ExecTx(fn)`.
  - `Rollback` change: after finding `target`, decrypt `target.EncryptedValue` with `v.key` (AAD-aware); on failure return `fmt.Errorf("version %d predates a KDF migration", version)`; then archive current (existing `AddHistory` block) and `SetSecret(name, plaintext, target.Tags)` (re-encrypt).
  - `SetSecret/GetSecret/GetAllSecrets/Rollback` encrypt/decrypt become AAD-aware: `if v.aad != nil → EncryptWithAAD/DecryptWithAAD else Encrypt/Decrypt` (helper methods `v.encrypt/pt, v.decrypt`).
  - `MigrateKDF` params branch: if `GetMeta("kdf_time") != ""` → `newKey = enc.DeriveKeyFromPassword(rawKey, salt, crypto.DefaultKDFParams())`; inside the tx, after re-encrypting all secrets also `SetMeta("kdf_time"/"kdf_memory"/"kdf_threads", ...)` to defaults. SQLite branch unchanged.

- [ ] **Step 1: Write failing tests**

Using the existing `testVault` helper pattern in `vault_test.go`; add a git-backed variant:

```go
func newTestGitVault(t *testing.T) *Vault {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	s, err := store.NewGitStore(repo, store.GitOptions{})
	if err != nil {
		t.Fatalf("git store: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	enc := crypto.NewAESGCM()
	kp := keyring.NewPasswordProvider(nil, false)
	t.Setenv("PSST_PASSWORD", "test-password")
	return New(enc, kp, s)
}

func TestVaultGitUnlockAADRoundTrip(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	if err := v.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := v.SetSecret("KEY", []byte("secret123"), []string{"prod"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := v.GetSecret("KEY")
	if err != nil || string(got.Value) != "secret123" {
		t.Fatalf("get: %v", got, err)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "prod" {
		t.Fatalf("tags = %v", got.Tags)
	}
}

func TestVaultRetagSecret(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	_ = v.Unlock()
	_ = v.SetSecret("KEY", []byte("secret123"), []string{"prod"})
	if err := v.RetagSecret("KEY", []string{"test"}); err != nil {
		t.Fatalf("retag: %v", err)
	}
	got, _ := v.GetSecret("KEY")
	if got.Tags[0] != "test" {
		t.Fatalf("tag = %v", got.Tags)
	}
}

func TestVaultRollbackReencrypts(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	_ = v.Unlock()
	_ = v.SetSecret("KEY", []byte("v1"), nil)
	_ = v.SetSecret("KEY", []byte("v2"), nil)
	if err := v.Rollback("KEY", 1); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, _ := v.GetSecret("KEY")
	if string(got.Value) != "v1" {
		t.Fatalf("value = %q, want v1", got.Value)
	}
}

func TestVaultBatchSingleTransport(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	_ = v.Unlock()
	err := v.Batch(func() error {
		for _, n := range []string{"A1", "B2"} {
			if err := v.SetSecret(n, []byte("x"), nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	metas, _ := v.ListSecrets()
	if len(metas) != 2 {
		t.Fatalf("metas = %d", len(metas))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vault/ -run 'GitUnlock|Retag|RollbackReencrypts|BatchSingle' -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

In `internal/vault/vault.go`:

`Unlock()` — insert the git branch after `rawKey` is fetched, replacing the current switch head:

```go
	kdfVersion := v.readKDFVersion()
	var key []byte

	if timeStr, _ := v.store.GetMeta("kdf_time"); timeStr != "" {
		saltB64, _ := v.store.GetMeta("kdf_salt")
		salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
		if decodeErr != nil {
			return fmt.Errorf("decode kdf_salt: %w", decodeErr)
		}
		params := crypto.KDFParams{}
		params.Time = uint32(atoiMeta(v.store, "kdf_time"))
		params.Memory = uint32(atoiMeta(v.store, "kdf_memory"))
		params.Threads = uint8(atoiMeta(v.store, "kdf_threads"))
		key, err = v.enc.DeriveKeyFromPassword(rawKey, salt, params)
		if err != nil {
			return fmt.Errorf("derive key: %w", err)
		}
		v.key = key
		if aadStr, _ := v.store.GetMeta("vault_aad"); aadStr != "" {
			v.aad = []byte(aadStr)
		}
		if gs, ok := v.store.(*store.GitStore); ok {
			gs.SetUnlockedFingerprint(saltB64 + "|" + timeStr + "|" +
				itoa(uint64(params.Memory)) + "|" + itoa(uint64(params.Threads)))
		}
		return nil
	}

	switch kdfVersion {
	...existing switch unchanged...
```

Helpers `atoiMeta` / `itoa` are thin `strconv` wrappers (add unexported at file bottom). `Vault` struct gains `aad []byte`.

Encrypt/decrypt helpers (used by SetSecret/GetSecret/GetAllSecrets/Rollback):

```go
func (v *Vault) encrypt(plaintext []byte) ([]byte, []byte, error) {
	if v.aad != nil {
		return v.enc.EncryptWithAAD(plaintext, v.key, v.aad)
	}
	return v.enc.Encrypt(plaintext, v.key)
}

func (v *Vault) decrypt(ciphertext, iv []byte) ([]byte, error) {
	if v.aad != nil {
		return v.enc.DecryptWithAAD(ciphertext, iv, v.key, v.aad)
	}
	return v.enc.Decrypt(ciphertext, iv, v.key)
}
```

`Rollback` — replace the final `return v.store.ExecTx(...)` block:

```go
	plaintext, err := v.decrypt(target.EncryptedValue, target.IV)
	if err != nil {
		return fmt.Errorf("version %d predates a KDF migration", version)
	}

	return v.store.ExecTx(func() error {
		newVersion := len(history) + 1
		if err = v.store.AddHistory(name, newVersion, current.EncryptedValue, current.IV, current.Tags); err != nil {
			return fmt.Errorf("archive history: %w", err)
		}
		return v.SetSecret(name, plaintext, target.Tags)
	})
```

`RetagSecret` and `Batch`:

```go
func (v *Vault) RetagSecret(name string, tags []string) error {
	sec, err := v.store.GetSecret(name)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("secret %q not found", name)
	}
	return v.store.ExecTx(func() error {
		return v.store.SetSecret(name, sec.EncryptedValue, sec.IV, tags)
	})
}

func (v *Vault) Batch(fn func() error) error {
	return v.store.ExecTx(fn)
}
```

`MigrateKDF` — head branch: if `GetMeta("kdf_time") != ""`, derive `newKey` via `v.enc.DeriveKeyFromPassword(rawKey, salt, crypto.DefaultKDFParams())` (salt from existing meta), and inside the tx append:

```go
		if err := v.store.SetMeta("kdf_time", strconv.Itoa(int(crypto.DefaultKDFParams().Time))); err != nil {
			return err
		}
		if err := v.store.SetMeta("kdf_memory", strconv.Itoa(int(crypto.DefaultKDFParams().Memory))); err != nil {
			return err
		}
		if err := v.store.SetMeta("kdf_threads", strconv.Itoa(int(crypto.DefaultKDFParams().Threads))); err != nil {
			return err
		}
```

Replace the three `v.enc.Encrypt/Decrypt` call sites in `SetSecret`/`GetSecret`/`GetAllSecrets`/`MigrateKDF` with `v.encrypt`/`v.decrypt`.

- [ ] **Step 4: Run tests**

Run: `go test ./... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/
git commit -m "feat: vault git-unlock branch, AAD, RetagSecret, Batch and re-encrypting rollback"
```

---

### Task 9: CLI wiring — storage config, factory, --storage flag, list-envs, git-mode validation

**Files:**
- Create: `internal/cli/vaultconfig.go`
- Create: `internal/cli/vaultconfig_test.go`
- Modify: `internal/cli/root.go` (factory + `--storage` flag + prompt provider for git)
- Modify: `internal/cli/list_envs.go` (detect `repo/psst.yaml`)
- Modify: `internal/cli/tag.go` (git routing: tag→RetagSecret replace; untag RangeArgs(1,2) → RetagSecret nil / tag-match check)
- Modify: `internal/cli/set.go` (reject `--tag` repeated with git storage)

**Interfaces:**
- Consumes: `store.NewGitStore`, `keyring.NewPasswordProvider`, vault helpers.
- Produces:
  - `type VaultConfig struct { Storage string; Remote string; PinSalt string; PinKDF crypto.KDFParams; HasPin bool }`, `func LoadVaultConfig(envDir string) (*VaultConfig, error)` (missing file → `&VaultConfig{}`), `func SaveVaultConfig(envDir string, cfg VaultConfig) error` — plain key:value file `config.yaml` (same subset parser style as Task 4; keys: `storage`, `remote`, `pin_salt`, `pin_kdf_time`, `pin_kdf_memory`, `pin_kdf_threads`), 0600.
  - `func resolveStorage(flagVal string, envDir string) (string, error)` — flag("sqlite"|"git") > config > autodetect (`vault.db` exists → sqlite; `repo/psst.yaml` exists → git; both → error "conflicting storage markers"; neither → sqlite).
  - `func openStore(envDir, storage, remote string, allowInsecure bool) (store.SecretStore, *store.GitStore, error)` — GitOptions wires `LoadPins/SavePins` to VaultConfig; validates remote scheme: `git://` → always error; `http://` → error unless `allowInsecure`; empty remote + git → local-only repo.
  - `getUnlockedVault` rewrite: resolve storage → openStore → SQLite: current path (`SQLitePath`); git: `keyring.NewPasswordProvider(nil, true)`; `InitSchema` only for sqlite (git InitSchema is non-destructive but called too — spec: idempotent no-op on valid repo; keep call for both); on `ErrSaltChanged`/`ErrKDFWeakened` exit 1 with rotation hint.
  - `func storageIsGit(global bool, env string) bool` helper for tag/set validation.
  - tag.go: `tagCmd.Run` → if git: `v.RetagSecret(name, []string{tag})`; untag: `Args: cobra.RangeArgs(1,2)`; 1 arg + git → `RetagSecret(name, nil)` (error if untagged comes from store: no file move); 1 arg + sqlite → error "tag argument required"; 2 args + git → verify current tag equals arg (read meta) else error, then `RetagSecret(nil)`; 2 args + sqlite → `RemoveTag` (unchanged).
  - set.go: `set` with `--tag a --tag b` (repeatable global flag from root) + git storage → `exitWithError("git vault supports a single tag")`.
  - list_envs.go `scanEnvDir`: also match `<env>/repo/psst.yaml`.

- [ ] **Step 1: Write failing tests**

```go
package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVaultConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := VaultConfig{Storage: "git", Remote: "git@host:vault.git", HasPin: true, PinSalt: "c2FsdA==", PinKDF: mustParams(t)}
	if err := SaveVaultConfig(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadVaultConfig(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Storage != "git" || got.Remote != "git@host:vault.git" || !got.HasPin || got.PinSalt != "c2FsdA==" {
		t.Fatalf("roundtrip = %+v", got)
	}
	if fi, err := os.Stat(filepath.Join(dir, "config.yaml")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("config perms: %v %v", fi, err)
	}
}

func TestResolveStorage(t *testing.T) {
	dir := t.TempDir()
	if s, _ := resolveStorage("", dir); s != "sqlite" {
		t.Fatalf("empty dir = %q", s)
	}
	os.WriteFile(filepath.Join(dir, "vault.db"), nil, 0600)
	if s, _ := resolveStorage("", dir); s != "sqlite" {
		t.Fatal("vault.db autodetect")
	}
	os.MkdirAll(filepath.Join(dir, "repo"), 0755)
	if _, err := resolveStorage("", dir); err == nil {
		t.Fatal("conflicting markers must error")
	}
	dir2 := t.TempDir()
	os.MkdirAll(filepath.Join(dir2, "repo", "secrets"), 0755)
	os.WriteFile(filepath.Join(dir2, "repo", "psst.yaml"), []byte("version: 1\n"), 0600)
	if s, _ := resolveStorage("", dir2); s != "git" {
		t.Fatal("repo autodetect")
	}
	SaveVaultConfig(dir2, VaultConfig{Storage: "sqlite"})
	if s, _ := resolveStorage("", dir2); s != "sqlite" {
		t.Fatal("config beats autodetect")
	}
	if s, _ := resolveStorage("git", dir2); s != "git" {
		t.Fatal("flag beats config")
	}
}

func TestRemoteSchemePolicy(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := openStore(dir, "git", "git://host/vault.git", false); err == nil {
		t.Fatal("git:// must always be rejected")
	}
	if _, _, err := openStore(dir, "git", "http://host/vault.git", false); err == nil {
		t.Fatal("http:// must be rejected without flag")
	}
	if _, _, err := openStore(dir, "git", "http://host/vault.git", true); err != nil {
		t.Fatalf("http with flag: %v", err)
	}
}
```

`mustParams` helper: `crypto.DefaultKDFParams()`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/ -run 'VaultConfig|ResolveStorage|RemoteScheme' -v`
Expected: FAIL.

- [ ] **Step 3: Implement** — all Produces items. `rootCmd.PersistentFlags().String("storage", "", "Storage backend: sqlite or git")`; thread through `getGlobalFlags` (add return value or separate getter). Update `getUnlockedVault(jsonOut, quiet, global, env)` signature to also read the flag via a new `getStorageFlag(cmd)` — simplest: keep `getGlobalFlags` and add `--storage` read where `cmd` is available; `getUnlockedVault` gains a `storage string` parameter (update all ~15 callers mechanically: pass `""` where flag absent on that command's context — NO: `--storage` is a persistent flag available on every command; read inside `getUnlockedVault` is impossible without cmd — so change signature to `getUnlockedVault(cmd *cobra.Command, jsonOut, quiet bool, global bool, env string)`; update every caller, one-line each).

- [ ] **Step 4: Run tests**

Run: `go test ./... -v`
Expected: PASS (fix mechanical callers until build green).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/
git commit -m "feat: storage selection, vault config, git-mode tag/untag and list-envs detection"
```

---

### Task 10: Commands — init --storage git, psst sync, migrate kdf/storage

**Files:**
- Modify: `internal/cli/init.go`
- Create: `internal/cli/sync.go`
- Modify: `internal/cli/migrate.go` (subcommands)
- Modify: `internal/cli/import.go` (Batch wrap)

**Interfaces:**
- Consumes: Tasks 6–9.
- Produces:
  - `init`: flags `--storage` (shared), `--remote`, `--allow-insecure-remote`. Git branch: require PSST_PASSWORD or TTY (prompt); `envDir := vault.FindVaultDir`; clone remote into `envDir/repo` when remote given (empty remote OK → `git init` path inside `NewGitStore`+`InitSchema`); write `VaultConfig{Storage: git, Remote, pins}`; push initial commit; message "Git vault created at <envDir>/repo (remote: <remote>)". Never touches keychain. SQLite branch unchanged.
  - `psst sync [--discard-local] [--confirm]`: resolve env dir; require git storage (`storageIsGit`); open `GitStore` directly (no vault unlock needed); `--discard-local`: require `--confirm` unless TTY-confirm; else `Sync()`; map `ErrNoRemote` → warning "working locally, no remote configured"; conflict error passes through with its hint.
  - `migrate`: parent command with `kdf` and `storage` subcommands; bare `psst migrate` (no args) keeps KDF behavior via `Run` on parent with `Args: cobra.NoArgs` only when no subcommand matched — implement parent `Run` = old KDF body, `subcommands` registered; cobra runs parent Run only when called bare.
  - `migrate storage --to git --remote <url> [--allow-insecure-remote]`: open SQLite vault (source; must exist), check `GetMeta("kdf_version") != "1"` else exit "vault uses legacy KDF; run `psst migrate kdf` first"; `GetAllSecrets` via old vault (plaintext in memory); pre-flight: every secret's tags ≤1 and match `store.ValidTag` else exit listing offenders "re-tag these secrets first: NAME (tag X)"; create git vault at `envDir/repo` (temp: `envDir/repo.new` then rename? — NO: keep simple, require target absent: if `repo/` exists → exit "git vault already exists"); `v2.Batch(set all)`; write `VaultConfig`; success message.
  - `import.go`: wrap the set-loop in `v.Batch(func() error {...})` (works for both backends).

- [ ] **Step 1: Write failing integration tests**

Create `tests/git_storage_test.go` (reuses `TestMain` binary):

```go
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func (e *testEnv) run(args ...string) (string, int) {
	e.t.Helper()
	home := filepath.Join(e.dir, "home")
	os.MkdirAll(home, 0755)
	cmd := exec.Command(e.binary, args...)
	cmd.Dir = filepath.Join(e.dir, "work")
	os.MkdirAll(cmd.Dir, 0755)
	cmd.Env = append(os.Environ(), "HOME="+home, "PSST_PASSWORD=test-password", "PSST_GLOBAL=1")
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		code = -1
	}
	return string(out), code
}

func (e *testEnv) bareRemote(t *testing.T) string {
	t.Helper()
	p := filepath.Join(e.dir, "remote.git")
	if out, err := exec.Command("git", "init", "--bare", p).CombinedOutput(); err != nil {
		t.Fatalf("bare: %v\n%s", err, out)
	}
	return p
}

func TestGitStorageLifecycle(t *testing.T) {
	e := newTestEnv(t)
	remote := e.bareRemote(t)

	if out, code := e.run("init", "--storage", "git", "--remote", remote); code != 0 {
		t.Fatalf("init: %s", out)
	}
	if out, code := e.run("set", "API_KEY", "--stdin"); code != 0 {
		t.Fatalf("set: %s", out)
	} else if !strings.Contains(out, "[REDACTED]") && !strings.Contains(out, "✓") {
		t.Fatalf("set out: %s", out)
	}
	out, code := e.run("list")
	if code != 0 || !strings.Contains(out, "API_KEY") {
		t.Fatalf("list: %s (%d)", out, code)
	}
	out, _ = e.run("tag", "API_KEY", "prod")
	if !strings.Contains(out, "Tagged") && !strings.Contains(out, "✓") {
		t.Fatalf("tag: %s", out)
	}
	out, code = e.run("--tag", "prod", "--", "sh", "-c", "test -n \"$API_KEY\"")
	if code != 0 {
		t.Fatalf("tagged exec: %s", out)
	}
	out, code = e.run("history", "API_KEY")
	if code != 0 {
		t.Fatalf("history: %s", out)
	}
	if out, code = e.run("untag", "API_KEY"); code != 0 {
		t.Fatalf("untag: %s", out)
	}
}

func TestGitStorageSecondMachine(t *testing.T) {
	e := newTestEnv(t)
	remote := e.bareRemote(t)
	e.run("init", "--storage", "git", "--remote", remote)
	e.run("set", "SHARED_KEY", "--stdin")

	home2 := filepath.Join(e.dir, "home2")
	os.MkdirAll(home2, 0755)
	cmd := exec.Command(e.binary, "set", "OTHER_KEY", "--stdin")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "HOME="+home2, "PSST_PASSWORD=test-password", "PSST_GLOBAL=1")
	cmd.Stdin = strings.NewReader("other-value\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("second machine set: %s", out)
	}
	cmd2 := exec.Command(e.binary, "list")
	cmd2.Env = cmd.Env
	out2, _ := cmd2.CombinedOutput()
	if !strings.Contains(string(out2), "SHARED_KEY") || !strings.Contains(string(out2), "OTHER_KEY") {
		t.Fatalf("second machine must see both: %s", out2)
	}
}

func TestSyncDiscardLocal(t *testing.T) {
	e := newTestEnv(t)
	remote := e.bareRemote(t)
	e.run("init", "--storage", "git", "--remote", remote)

	home2 := filepath.Join(e.dir, "home2")
	os.MkdirAll(home2, 0755)
	run2 := func(args ...string) string {
		c := exec.Command(e.binary, args...)
		c.Env = append(os.Environ(), "HOME="+home2, "PSST_PASSWORD=test-password", "PSST_GLOBAL=1")
		out, _ := c.CombinedOutput()
		return string(out)
	}
	e.run("set", "KEY", "--stdin")
	run2("set", "KEY", "--stdin")
	out, _ := run2("set", "KEY2", "--stdin")
	if !strings.Contains(out, "discard-local") {
		t.Fatalf("conflict must hint discard-local: %s", out)
	}
	run2("sync", "--discard-local", "--confirm")
	if out := run2("set", "KEY2", "--stdin"); strings.Contains(out, "✗") {
		t.Fatalf("recovery failed: %s", out)
	}
}

func TestMigrateStorage(t *testing.T) {
	e := newTestEnv(t)
	e.run("init")
	e.run("set", "OLD_KEY", "--stdin")
	out, code := e.run("migrate", "storage", "--to", "git")
	if code != 0 {
		t.Fatalf("migrate storage: %s (%d)", out, code)
	}
	out, _ = e.run("list")
	if !strings.Contains(out, "OLD_KEY") {
		t.Fatalf("migrated secret missing: %s", out)
	}
	if out, code := e.run("get", "OLD_KEY"); code != 0 {
		t.Fatalf("get after migrate: %s", out)
	}
}

func TestMigrateRejectsV1AndBadTags(t *testing.T) {
	e := newTestEnv(t)
	e.run("init")
	e.run("set", "KEY", "--stdin")
	if out, code := e.run("migrate", "storage", "--to", "git"); code != 0 && !strings.Contains(out, "KDF") {
		t.Logf("v1 rejection or pass: %s", out)
	}
	e.run("tag", "KEY", "Prod")
	if out, code := e.run("migrate", "storage", "--to", "git"); code == 0 || !strings.Contains(out, "Prod") {
		t.Fatalf("bad tag pre-flight: %s", out)
	}
}
```

Note: `set --stdin` needs stdin wired — set `cmd.Stdin = strings.NewReader("value\n")` in `run` helper (add `withStdin` variant).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./tests/ -run 'GitStorage|SyncDiscard|MigrateStorage|MigrateRejects' -v`
Expected: FAIL (unknown flags / commands).

- [ ] **Step 3: Implement** — all Produces items across the four files. `InitGitVault` logic lives in `internal/cli/init.go` + `internal/store` helpers only via public API (`NewGitStore`, `InitSchema`, `Sync`, config save). For `migrate storage` decrypt: use old vault's `GetAllSecrets()` (returns plaintext map). Fresh git vault at `envDir/repo`: `store.NewGitStore(repo, GitOptions{Remote: remote})` → `InitSchema()` (mints salt) → `vault.New(enc, passwordProvider, gs)` → `Unlock()` → `Batch(set)` → `Sync()`.

- [ ] **Step 4: Run tests**

Run: `go test ./... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/ tests/git_storage_test.go
git commit -m "feat: init --storage git, psst sync and migrate kdf/storage commands"
```

---

### Task 11: Docs and security rules

**Files:**
- Modify: `docs/rules/security.md`
- Modify: `README.md`
- Modify: `docs/ru/README.md` (mirror section)

**Interfaces:**
- Consumes: final behavior of Tasks 1–10.
- Produces: documented behavior.

- [ ] **Step 1: Update `docs/rules/security.md`**

Replace the "Never send secrets over network" bullet (line 58) with:

```markdown
- **Never send plaintext secrets over network.** The git remote of a git-storage
  vault contains only AES-256-GCM ciphertext (AAD-bound to vault metadata);
  secret names are visible as file names by design. The web UI (future phase)
  binds to localhost with a mandatory token. Plaintext egress inventory: the
  child process environment (runner) is the existing channel; `psst render`
  (future phase) adds a 0600 file channel. `psst get` and `psst export` remain
  explicit operator-initiated exceptions.
```

Add a "Git storage" subsection after "Encryption":

```markdown
## Git Storage

- One file per secret: `secrets/[tag/]NAME.enc` = base64(IV ‖ AES-256-GCM ciphertext).
- `psst.yaml` is untrusted input: strict validation, salt strictly immutable,
  KDF parameters only monotonically strengthened (pins in `.psst/config.yaml`).
- All git invocations run with `core.hooksPath=/dev/null`, `GIT_TERMINAL_PROMPT=0`,
  `GIT_CONFIG_NOSYSTEM=1`, an empty `GIT_CONFIG_GLOBAL`, and a subcommand allowlist.
- Git vaults derive keys strictly from the password via Argon2id — no base64
  passthrough, no OS keychain.
- A repo lock (`flock`) serializes all git mutations on a clone.
```

- [ ] **Step 2: Update READMEs**

Add a "Git Storage (multi-machine)" section after "Environments" in both `README.md` and `docs/ru/README.md` (Russian mirror):

````markdown
### Git Storage (multi-machine)

```bash
psst init --storage git --remote git@github.com:me/psst-vault.git
# or a local bare repo: --remote /path/to/vault.git
echo "sk-live-abc" | psst set STRIPE_KEY --stdin
psst sync
```

- Every command pulls before reading and rebases+pushes on writes.
- Reads work offline; writes require the remote (or warn on local-only repos).
- One file per secret, tags are directories (`secrets/prod/DB_PASS.enc`), a
  single tag per secret; history is git history.
- Same `PSST_PASSWORD` on every machine (or the interactive prompt).
- `psst migrate storage --to git` converts an existing SQLite vault.

Migration from SQLite: `psst migrate kdf` first if the vault is on the legacy
KDF, then `psst migrate storage --to git --remote <url>`.
````

- [ ] **Step 3: Run full test suite**

Run: `make test`
Expected: PASS, zero failures.

- [ ] **Step 4: Verify no keychain writes for git vaults**

Run: `grep -rn "SetKey" internal/cli/init.go` — confirm the git branch never calls `kp.SetKey`.

- [ ] **Step 5: Commit**

```bash
git add docs/rules/security.md README.md docs/ru/README.md
git commit -m "docs: git storage backend documentation and security rules"
```

---

## Final Verification

- [ ] `make test` green
- [ ] `grep -rn "go.mod" go.sum` unchanged (`git diff --stat go.mod go.sum` empty)
- [ ] Manual smoke (optional): `cd /tmp && git init --bare v.git && psst init --storage git --remote /tmp/v.git && echo x | psst set A --stdin && psst list && psst sync`

## Spec Coverage Map

| Spec section | Tasks |
|---|---|
| §1.1 layout, psst.yaml, validation, AAD, schemes, pins | 1, 4, 9 |
| §1.2 GitStore 14 methods, InitSchema, history, ExecTx, path safety, Author | 2, 6, 7 |
| §1.3 sync protocol, lock, allowlist, env hardening, recovery, stale-key | 5, 7, 10 |
| §1.4 CLI UX, storage priority, password-only, prompt, wiring, list-envs, scan note | 3, 9, 10 |
| §1.5 testing scenarios | 6, 7, 10 (integration) |
| §4 security rules update | 11 |
| §6 phase 1 scope (serve/render excluded) | — (phases 2–3) |

package vault

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)

type testKeyProvider struct {
	enc *crypto.AESGCM
	key []byte
}

func (t *testKeyProvider) GetRawKey(_, _ string) (string, error) {
	if t.key == nil {
		return "", errors.New("no key")
	}
	return hex.EncodeToString(t.key), nil
}

func (t *testKeyProvider) SetKey(_, _ string, key []byte) error {
	t.key = key
	return nil
}

func (t *testKeyProvider) IsAvailable() bool { return true }

func (t *testKeyProvider) GenerateKey() ([]byte, error) {
	return t.enc.GenerateKey()
}

func setupTestVault(t *testing.T) *Vault {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.InitSchema(); err != nil {
		t.Fatal(err)
	}

	enc := crypto.NewAESGCM()
	kp := &testKeyProvider{enc: enc, key: nil}

	v := New(enc, kp, s)

	key, _ := enc.GenerateKey()
	kp.key = key
	v.key = key

	return v
}

func TestSetGetSecret(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	if err := v.SetSecret("API_KEY", []byte("secret123"), []string{"prod"}); err != nil {
		t.Fatal(err)
	}

	sec, err := v.GetSecret("API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Value) != "secret123" {
		t.Fatalf("value = %q, want %q", string(sec.Value), "secret123")
	}
	if len(sec.Tags) != 1 || sec.Tags[0] != "prod" {
		t.Fatalf("tags = %v", sec.Tags)
	}
}

func TestListSecrets(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	v.SetSecret("A", []byte("val_a"), nil)
	v.SetSecret("B", []byte("val_b"), nil)

	list, err := v.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
}

func TestDeleteSecret(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	v.SetSecret("KEY", []byte("val"), nil)
	v.DeleteSecret("KEY")

	sec, _ := v.GetSecret("KEY")
	if sec != nil {
		t.Fatal("secret should be nil after delete")
	}
}

func TestHistoryAndRollback(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	v.SetSecret("KEY", []byte("v1"), nil)
	v.SetSecret("KEY", []byte("v2"), nil)
	v.SetSecret("KEY", []byte("v3"), nil)

	history, err := v.GetHistory("KEY")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) < 2 {
		t.Fatalf("history len = %d, want >= 2", len(history))
	}

	err = v.Rollback("KEY", 1)
	if err != nil {
		t.Fatal(err)
	}

	sec, _ := v.GetSecret("KEY")
	if string(sec.Value) != "v1" {
		t.Fatalf("after rollback value = %q, want %q", string(sec.Value), "v1")
	}
}

func TestGetHistoryMapsAuthor(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

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

func TestTags(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	v.SetSecret("KEY", []byte("val"), nil)
	v.AddTag("KEY", "aws")
	v.AddTag("KEY", "prod")

	sec, _ := v.GetSecret("KEY")
	if len(sec.Tags) != 2 {
		t.Fatalf("tags = %v, want 2", sec.Tags)
	}

	v.RemoveTag("KEY", "aws")
	sec, _ = v.GetSecret("KEY")
	if len(sec.Tags) != 1 || sec.Tags[0] != "prod" {
		t.Fatalf("after remove tags = %v", sec.Tags)
	}
}

func TestGetSecretsByTags(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	v.SetSecret("A", []byte("val_a"), []string{"aws", "prod"})
	v.SetSecret("B", []byte("val_b"), []string{"stripe"})
	v.SetSecret("C", []byte("val_c"), []string{"prod"})

	result, err := v.GetSecretsByTags([]string{"aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Name != "A" {
		t.Fatalf("result = %v", result)
	}

	result2, _ := v.GetSecretsByTags([]string{"prod"})
	if len(result2) != 2 {
		t.Fatalf("prod filter: len = %d, want 2", len(result2))
	}
}

func TestGetAllSecrets(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	v.SetSecret("A", []byte("val_a"), nil)
	v.SetSecret("B", []byte("val_b"), nil)

	all, err := v.GetAllSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if string(all["A"]) != "val_a" || string(all["B"]) != "val_b" {
		t.Fatalf("all = %v", all)
	}
}

func TestVault_LockedOperations(t *testing.T) {
	enc := crypto.NewAESGCM()
	kp := &testKeyProvider{key: nil}
	s, err := store.NewSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.InitSchema()

	v := New(enc, kp, s)

	if err = v.SetSecret("A", []byte("val"), nil); err == nil {
		t.Fatal("SetSecret on locked vault should fail")
	}
	if _, err = v.GetSecret("A"); err == nil {
		t.Fatal("GetSecret on locked vault should fail")
	}
	if _, err = v.GetAllSecrets(); err == nil {
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
		{"env_prod", false, "prod", ".psst/envs/prod/vault.db"},
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
	defer v.Close()
	err := v.Rollback("NONEXISTENT", 1)
	if err == nil {
		t.Fatal("rollback nonexistent secret should fail")
	}
}

func TestRollback_VersionNotFound(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	v.SetSecret("TEST", []byte("val"), nil)
	err := v.Rollback("TEST", 999)
	if err == nil {
		t.Fatal("rollback nonexistent version should fail")
	}
}

func setupTestVaultV1(t *testing.T) *Vault {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.InitSchema(); err != nil {
		t.Fatal(err)
	}

	enc := crypto.NewAESGCM()
	kp := &testKeyProvider{enc: enc, key: nil}

	v := New(enc, kp, s)

	rawKey, err := enc.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	kp.key = rawKey

	v1Key, err := enc.KeyToBuffer(hex.EncodeToString(rawKey))
	if err != nil {
		t.Fatal(err)
	}
	v.key = v1Key

	if err = s.SetMeta("kdf_version", "1"); err != nil {
		t.Fatal(err)
	}

	return v
}

func TestMigrateKDF(t *testing.T) {
	v := setupTestVaultV1(t)
	defer v.Close()

	secrets := map[string]string{
		"API_KEY": "secret123",
		"DB_HOST": "localhost",
		"DB_PORT": "5432",
	}
	for name, val := range secrets {
		if err := v.SetSecret(name, []byte(val), nil); err != nil {
			t.Fatal(err)
		}
	}

	oldKey := make([]byte, len(v.key))
	copy(oldKey, v.key)

	if err := v.MigrateKDF(); err != nil {
		t.Fatalf("MigrateKDF: %v", err)
	}

	kdfVer, _ := v.store.GetMeta("kdf_version")
	if kdfVer != "2" {
		t.Fatalf("kdf_version = %q, want %q", kdfVer, "2")
	}

	rawKeyHex, _ := v.kp.GetRawKey(serviceName, accountName)
	saltB64, _ := v.store.GetMeta("kdf_salt")
	var v2Key []byte
	var deriveErr error
	if saltB64 != "" {
		salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		v2Key, deriveErr = v.enc.KeyToBufferV2WithSalt(rawKeyHex, salt)
	} else {
		v2Key, deriveErr = v.enc.KeyToBufferV2(rawKeyHex)
	}
	if deriveErr != nil {
		t.Fatal(deriveErr)
	}
	v.key = v2Key

	for name, want := range secrets {
		sec, err := v.GetSecret(name)
		if err != nil {
			t.Fatalf("GetSecret(%q) after migrate: %v", name, err)
		}
		if string(sec.Value) != want {
			t.Fatalf("secret %q = %q, want %q", name, string(sec.Value), want)
		}
	}

	if hex.EncodeToString(oldKey) == hex.EncodeToString(v2Key) {
		t.Fatal("key should have changed after KDF migration")
	}
}

func TestPerVaultSalt(t *testing.T) {
	dir := t.TempDir()
	enc := crypto.NewAESGCM()

	path1 := filepath.Join(dir, "vault1.db")
	kp1 := &testKeyProvider{enc: enc, key: nil}
	if err := InitVault(path1, enc, kp1, InitOptions{SkipKeychain: true}); err != nil {
		t.Fatal(err)
	}

	s1, err := store.NewSQLite(path1)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	salt1, _ := s1.GetMeta("kdf_salt")
	if salt1 == "" {
		t.Fatal("kdf_salt should be set")
	}

	path2 := filepath.Join(dir, "vault2.db")
	kp2 := &testKeyProvider{enc: enc, key: nil}
	if err := InitVault(path2, enc, kp2, InitOptions{SkipKeychain: true}); err != nil {
		t.Fatal(err)
	}

	s2, err := store.NewSQLite(path2)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	salt2, _ := s2.GetMeta("kdf_salt")
	if salt2 == "" {
		t.Fatal("kdf_salt should be set")
	}

	if salt1 == salt2 {
		t.Fatal("two different vaults should have different salts")
	}
}

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
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.Value) != "secret123" {
		t.Fatalf("value = %q", got.Value)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "prod" {
		t.Fatalf("tags = %v", got.Tags)
	}
	all, err := v.GetAllSecrets()
	if err != nil || len(all) != 1 {
		t.Fatalf("all: %v %v", all, err)
	}
}

func TestVaultGitAADActuallyBinds(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	_ = v.Unlock()
	_ = v.SetSecret("KEY", []byte("secret123"), nil)
	salt, _ := v.store.GetMeta("kdf_salt")
	if salt == "" {
		t.Fatal("salt")
	}
	forgedKey, err := v.enc.DeriveKeyFromPassword("test-password", []byte("othersalt-16byt"), crypto.DefaultKDFParams())
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := v.store.GetSecret("KEY")
	if _, err = v.enc.DecryptWithAAD(stored.EncryptedValue, stored.IV, forgedKey, []byte("psst:v1:argon2id:"+salt)); err == nil {
		t.Fatal("wrong key must fail via AAD+GCM")
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
	if err := v.RetagSecret("KEY", nil); err != nil {
		t.Fatalf("untag: %v", err)
	}
	got, _ = v.GetSecret("KEY")
	if len(got.Tags) != 0 {
		t.Fatalf("tags after untag = %v", got.Tags)
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

func TestVaultListSecretsMapsUpdatedBy(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	if err := v.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := v.SetSecret("KEY", []byte("secret123"), nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	metas, err := v.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 1 || metas[0].UpdatedBy == "" {
		t.Fatalf("updatedBy not mapped: %+v", metas)
	}
}

func TestVaultBatchSingleCommit(t *testing.T) {
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

func newBareRemoteVault(t *testing.T) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return remote
}

func newGitVaultStore(t *testing.T) (*store.GitStore, string) {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	g, err := store.NewGitStore(repo, store.GitOptions{})
	if err != nil {
		t.Fatalf("git store: %v", err)
	}
	if err := g.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	return g, repo
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
	oldTime, _ := gs.GetMeta("kdf_time")
	oldMemory, _ := gs.GetMeta("kdf_memory")

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
	newTime, _ := gs.GetMeta("kdf_time")
	newMemory, _ := gs.GetMeta("kdf_memory")
	if newTime != oldTime || newMemory != oldMemory {
		t.Fatalf("params changed: %s/%s was %s/%s", newTime, newMemory, oldTime, oldMemory)
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
	other, err := store.CloneGitVault(remote, filepath.Join(t.TempDir(), "repo2"), store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.InitSchema(); err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyAllDecryptable(); err != nil {
		t.Fatal(err)
	}
	ov := vaultFromPassword(t, other, "test-password")
	if err := ov.SetSecret("LATE", []byte("late-secret456"), nil); err != nil {
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
	g, repo := newGitVaultStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("BAD", []byte("garbage-not-base64!"), iv, nil); err != nil {
		t.Fatal(err)
	}
	v := vaultFromPassword(t, g, "test-password")
	saltBefore, _ := g.GetMeta("kdf_salt")
	logBefore, _ := store.NewGitRunner(repo).Run("log", "--format=%H")
	if err := v.VerifyAllDecryptable(); err == nil {
		t.Fatal("pre-flight must fail on garbage")
	}
	if _, err := v.Rotate("new-password"); err == nil {
		t.Fatal("rotate must abort")
	}
	salt, _ := g.GetMeta("kdf_salt")
	if salt != saltBefore {
		t.Fatalf("salt changed on abort: %q was %q", salt, saltBefore)
	}
	logAfter, _ := store.NewGitRunner(repo).Run("log", "--format=%H")
	if logAfter != logBefore {
		t.Fatal("commits landed on abort")
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

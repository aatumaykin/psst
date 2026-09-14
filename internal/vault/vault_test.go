package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/kdf"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)

type testKeyProvider struct {
	enc *crypto.AESGCM
	key []byte
}

func (t *testKeyProvider) GetRawKey(_, _ string) ([]byte, error) {
	if t.key == nil {
		return nil, errors.New("no key")
	}
	return []byte(hex.EncodeToString(t.key)), nil
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
	ctx := context.Background()

	if err := v.SetSecret(ctx, "API_KEY", []byte("secret123"), []string{"prod"}); err != nil {
		t.Fatal(err)
	}

	sec, err := v.GetSecret(ctx, "API_KEY")
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
	ctx := context.Background()

	v.SetSecret(ctx, "A", []byte("val_a"), nil)
	v.SetSecret(ctx, "B", []byte("val_b"), nil)

	list, err := v.ListSecrets(ctx)
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
	ctx := context.Background()

	v.SetSecret(ctx, "KEY", []byte("val"), nil)
	v.DeleteSecret(ctx, "KEY")

	sec, _ := v.GetSecret(ctx, "KEY")
	if sec != nil {
		t.Fatal("secret should be nil after delete")
	}
}

func TestHistoryAndRollback(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "KEY", []byte("v1"), nil)
	v.SetSecret(ctx, "KEY", []byte("v2"), nil)
	v.SetSecret(ctx, "KEY", []byte("v3"), nil)

	history, err := v.GetHistory(ctx, "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) < 2 {
		t.Fatalf("history len = %d, want >= 2", len(history))
	}

	err = v.Rollback(ctx, "KEY", 1)
	if err != nil {
		t.Fatal(err)
	}

	sec, _ := v.GetSecret(ctx, "KEY")
	if string(sec.Value) != "v1" {
		t.Fatalf("after rollback value = %q, want %q", string(sec.Value), "v1")
	}
}

func TestGetHistoryMapsAuthor(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	if err := v.SetSecret(ctx, "API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := v.SetSecret(ctx, "API_KEY", []byte("secret456"), nil); err != nil {
		t.Fatalf("set2: %v", err)
	}
	entries, err := v.GetHistory(ctx, "API_KEY")
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
	ctx := context.Background()

	v.SetSecret(ctx, "KEY", []byte("val"), nil)
	v.AddTag(ctx, "KEY", "aws")
	v.AddTag(ctx, "KEY", "prod")

	sec, _ := v.GetSecret(ctx, "KEY")
	if len(sec.Tags) != 2 {
		t.Fatalf("tags = %v, want 2", sec.Tags)
	}

	v.RemoveTag(ctx, "KEY", "aws")
	sec, _ = v.GetSecret(ctx, "KEY")
	if len(sec.Tags) != 1 || sec.Tags[0] != "prod" {
		t.Fatalf("after remove tags = %v", sec.Tags)
	}
}

func TestGetSecretsByTags(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "A", []byte("val_a"), []string{"aws", "prod"})
	v.SetSecret(ctx, "B", []byte("val_b"), []string{"stripe"})
	v.SetSecret(ctx, "C", []byte("val_c"), []string{"prod"})

	result, err := v.GetSecretsByTags(ctx, []string{"aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Name != "A" {
		t.Fatalf("result = %v", result)
	}

	result2, _ := v.GetSecretsByTags(ctx, []string{"prod"})
	if len(result2) != 2 {
		t.Fatalf("prod filter: len = %d, want 2", len(result2))
	}
}

func TestGetAllSecrets(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "A", []byte("val_a"), nil)
	v.SetSecret(ctx, "B", []byte("val_b"), nil)

	all, err := v.GetAllSecrets(ctx)
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
	ctx := context.Background()

	v := New(enc, kp, s)

	if err = v.SetSecret(ctx, "A", []byte("val"), nil); err == nil {
		t.Fatal("SetSecret on locked vault should fail")
	}
	if _, err = v.GetSecret(ctx, "A"); err == nil {
		t.Fatal("GetSecret on locked vault should fail")
	}
	if _, err = v.GetAllSecrets(ctx); err == nil {
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
	ctx := context.Background()
	err := v.Rollback(ctx, "NONEXISTENT", 1)
	if err == nil {
		t.Fatal("rollback nonexistent secret should fail")
	}
}

func TestRollback_VersionNotFound(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()
	v.SetSecret(ctx, "TEST", []byte("val"), nil)
	err := v.Rollback(ctx, "TEST", 999)
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

	rawKeyStr := hex.EncodeToString(rawKey)
	v1Key, err := enc.KeyToBuffer(rawKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	v.key = v1Key
	v.rawKey = []byte(rawKeyStr)

	ctx := context.Background()
	if err = s.SetMeta(ctx, "kdf_version", "1"); err != nil {
		t.Fatal(err)
	}

	return v
}

func TestMigrateKDF(t *testing.T) {
	v := setupTestVaultV1(t)
	defer v.Close()
	ctx := context.Background()

	secrets := map[string]string{
		"API_KEY": "secret123",
		"DB_HOST": "localhost",
		"DB_PORT": "5432",
	}
	for name, val := range secrets {
		if err := v.SetSecret(ctx, name, []byte(val), nil); err != nil {
			t.Fatal(err)
		}
	}

	oldKey := make([]byte, len(v.key))
	copy(oldKey, v.key)

	if err := v.MigrateKDF(ctx); err != nil {
		t.Fatalf("MigrateKDF: %v", err)
	}

	kdfVer, _ := v.store.GetMeta(ctx, "kdf_version")
	if kdfVer != "2" {
		t.Fatalf("kdf_version = %q, want %q", kdfVer, "2")
	}

	rawKeyHex, _ := v.kp.GetRawKey(serviceName, accountName)
	saltB64, _ := v.store.GetMeta(ctx, "kdf_salt")
	var v2Key []byte
	var deriveErr error
	if saltB64 != "" {
		salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		v2Key, deriveErr = v.enc.KeyToBufferV2WithSalt(string(rawKeyHex), salt)
	} else {
		aesgcm, ok := v.enc.(*crypto.AESGCM)
		if !ok {
			t.Fatal("expected *crypto.AESGCM for legacy KeyToBufferV2")
		}
		v2Key, deriveErr = aesgcm.KeyToBufferV2(string(rawKeyHex)) //nolint:staticcheck // testing legacy V2 KDF path
	}
	if deriveErr != nil {
		t.Fatal(deriveErr)
	}
	v.key = v2Key

	for name, want := range secrets {
		sec, err := v.GetSecret(ctx, name)
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

func TestMigrateKDF_UpdatesKey(t *testing.T) {
	v := setupTestVaultV1(t)
	defer v.Close()
	ctx := context.Background()

	if err := v.SetSecret(ctx, "API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatal(err)
	}

	if err := v.MigrateKDF(ctx); err != nil {
		t.Fatalf("MigrateKDF: %v", err)
	}

	sec, err := v.GetSecret(ctx, "API_KEY")
	if err != nil {
		t.Fatalf("GetSecret after migrate without manual key fix: %v", err)
	}
	if string(sec.Value) != "secret123" {
		t.Fatalf("secret = %q, want %q", string(sec.Value), "secret123")
	}
}

func TestSetSecret_VersionCollision(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	for i := range 15 {
		if err := v.SetSecret(ctx, "KEY", fmt.Appendf(nil, "v%d", i), nil); err != nil {
			t.Fatalf("SetSecret iteration %d: %v", i, err)
		}
	}

	sec, err := v.GetSecret(ctx, "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Value) != "v14" {
		t.Fatalf("value = %q, want %q", string(sec.Value), "v14")
	}
}

func TestMigrateKDF_GeneratesSalt(t *testing.T) {
	v := setupTestVaultV1(t)
	defer v.Close()
	ctx := context.Background()

	if err := v.SetSecret(ctx, "TEST", []byte("value"), nil); err != nil {
		t.Fatal(err)
	}

	if err := v.MigrateKDF(ctx); err != nil {
		t.Fatal(err)
	}

	saltB64, err := v.store.GetMeta(ctx, "kdf_salt")
	if err != nil {
		t.Fatal(err)
	}
	if saltB64 == "" {
		t.Fatal("MigrateKDF should generate kdf_salt when migrating from V1")
	}

	sec, err := v.GetSecret(ctx, "TEST")
	if err != nil {
		t.Fatalf("GetSecret after migrate: %v", err)
	}
	if string(sec.Value) != "value" {
		t.Fatalf("value = %q, want %q", string(sec.Value), "value")
	}
}

func TestRollback_AfterPrunedHistory(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	for i := range 15 {
		if err := v.SetSecret(ctx, "KEY", fmt.Appendf(nil, "v%d", i), nil); err != nil {
			t.Fatalf("SetSecret iteration %d: %v", i, err)
		}
	}

	history, err := v.GetHistory(ctx, "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) == 0 {
		t.Fatal("expected history entries")
	}

	oldestVersion := history[0].Version

	err = v.Rollback(ctx, "KEY", oldestVersion)
	if err != nil {
		t.Fatalf("Rollback to version %d after pruning: %v", oldestVersion, err)
	}

	sec, err := v.GetSecret(ctx, "KEY")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("v%d", oldestVersion-1)
	if string(sec.Value) != want {
		t.Fatalf("after rollback value = %q, want %q", string(sec.Value), want)
	}
}

func TestMigrateKDF_ZeroesOldKey(t *testing.T) {
	v := setupTestVaultV1(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "K", []byte("val"), nil)

	oldKey := v.key

	v.MigrateKDF(ctx)

	allZero := true
	for _, b := range oldKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Fatal("old key should be zeroed after MigrateKDF")
	}
}

func TestUnlock_V2WithoutSaltFails(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()
	ctx := context.Background()

	enc := crypto.NewAESGCM()
	kp := &testKeyProvider{enc: enc, key: nil}
	rawKey, _ := enc.GenerateKey()
	kp.key = rawKey

	s.SetMeta(ctx, "kdf_version", "2")

	v := New(enc, kp, s)
	defer v.Close()

	err = v.Unlock(ctx)
	if err == nil {
		t.Fatal("Unlock should fail when kdf_salt is missing for V2")
	}
	if !strings.Contains(err.Error(), "kdf_salt") {
		t.Fatalf("expected kdf_salt error, got: %v", err)
	}
}

func TestPerVaultSalt(t *testing.T) {
	dir := t.TempDir()
	enc := crypto.NewAESGCM()
	ctx := context.Background()

	path1 := filepath.Join(dir, "vault1.db")
	kp1Key, _ := enc.GenerateKey()
	kp1 := &testKeyProvider{enc: enc, key: kp1Key}
	if err := InitVault(ctx, path1, enc, kp1, InitOptions{SkipKeychain: true}); err != nil {
		t.Fatal(err)
	}

	s1, err := store.NewSQLite(path1)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	salt1, _ := s1.GetMeta(ctx, "kdf_salt")
	if salt1 == "" {
		t.Fatal("kdf_salt should be set")
	}

	path2 := filepath.Join(dir, "vault2.db")
	kp2Key, _ := enc.GenerateKey()
	kp2 := &testKeyProvider{enc: enc, key: kp2Key}
	if initErr := InitVault(ctx, path2, enc, kp2, InitOptions{SkipKeychain: true}); initErr != nil {
		t.Fatal(initErr)
	}

	s2, storeErr := store.NewSQLite(path2)
	if storeErr != nil {
		t.Fatal(storeErr)
	}
	defer s2.Close()
	salt2, _ := s2.GetMeta(ctx, "kdf_salt")
	if salt2 == "" {
		t.Fatal("kdf_salt should be set")
	}

	if salt1 == salt2 {
		t.Fatal("two different vaults should have different salts")
	}
}

func TestSetSecret_NameTooLong(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	longName := strings.Repeat("A", 257)
	err := v.SetSecret(ctx, longName, []byte("val"), nil)
	if err == nil {
		t.Fatal("should reject long name")
	}
}

func TestSetSecret_ValueTooLong(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	longValue := make([]byte, 4097)
	err := v.SetSecret(ctx, "KEY", longValue, nil)
	if err == nil {
		t.Fatal("should reject long value")
	}
}

func TestUnlock_BruteForceProtection(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()
	ctx := context.Background()

	enc := crypto.NewAESGCM()
	rightKey, _ := enc.GenerateKey()
	rightKp := &testKeyProvider{enc: enc, key: rightKey}

	v := New(enc, rightKp, s)
	v.key = rightKey
	v.SetSecret(ctx, "TEST", []byte("verify"), nil)
	v.key = nil

	wrongKey, _ := enc.GenerateKey()
	wrongKey[0] ^= 0xFF
	wrongKp := &testKeyProvider{enc: enc, key: wrongKey}

	wrongV := New(enc, wrongKp, s)
	defer wrongV.Close()

	for range maxUnlockAttempts {
		wrongV.Unlock(ctx)
	}

	err = wrongV.Unlock(ctx)
	if err == nil {
		t.Fatal("should be locked after max failed attempts")
	}
}

func TestRequireUnlock_ReturnsErrorWhenLocked(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()

	enc := crypto.NewAESGCM()
	kp := &testKeyProvider{enc: enc, key: nil}

	v := New(enc, kp, s)
	defer v.Close()

	_, err = v.ListSecrets(context.Background())
	if err == nil {
		t.Fatal("ListSecrets on locked vault should fail")
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Fatalf("expected locked error, got: %v", err)
	}
}

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

func TestSetSecret_RejectsInvalidName(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	for _, name := range []string{"lower", "123ABC", "has-dash", "has space"} {
		err := v.SetSecret(ctx, name, []byte("val"), nil)
		if err == nil {
			t.Fatalf("SetSecret(%q) should be rejected", name)
		}
	}
}

func TestEmptyVault_RequiresCorrectPassword(t *testing.T) {
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

	wrongV := New(enc, wrongKp, s)
	defer wrongV.Close()

	if err = wrongV.Unlock(ctx); err == nil {
		t.Fatal("unlock with wrong key on empty vault should fail")
	}

	s2, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	v := New(enc, kp, s2)
	defer v.Close()

	if err = v.Unlock(ctx); err != nil {
		t.Fatalf("unlock with correct key on empty vault: %v", err)
	}
}

func TestReadKDFVersion_RejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()
	ctx := context.Background()

	enc := crypto.NewAESGCM()
	rightKey, _ := enc.GenerateKey()
	kp := &testKeyProvider{enc: enc, key: rightKey}

	s.SetMeta(ctx, "kdf_version", "99")

	v := New(enc, kp, s)
	defer v.Close()

	err = v.Unlock(ctx)
	if err == nil {
		t.Fatal("Unlock should fail with unknown KDF version")
	}
	if !strings.Contains(err.Error(), "unsupported KDF version") {
		t.Fatalf("expected unsupported KDF version error, got: %v", err)
	}
}

func TestRollback_AtomicOperation(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "KEY", []byte("v1"), nil)
	v.SetSecret(ctx, "KEY", []byte("v2"), nil)

	err := v.Rollback(ctx, "KEY", 1)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	sec, err := v.GetSecret(ctx, "KEY")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(sec.Value) != "v1" {
		t.Fatalf("after rollback value = %q, want %q", string(sec.Value), "v1")
	}
}

func TestExponentialLockout(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()
	ctx := context.Background()

	enc := crypto.NewAESGCM()
	rightKey, _ := enc.GenerateKey()
	rightKp := &testKeyProvider{enc: enc, key: rightKey}

	v := New(enc, rightKp, s)
	v.key = rightKey
	v.SetSecret(ctx, "TEST", []byte("verify"), nil)
	v.key = nil

	wrongKey, _ := enc.GenerateKey()
	wrongKey[0] ^= 0xFF
	wrongKp := &testKeyProvider{enc: enc, key: wrongKey}

	wrongV := New(enc, wrongKp, s)
	defer wrongV.Close()

	for range maxUnlockAttempts {
		wrongV.Unlock(ctx)
	}

	err = wrongV.Unlock(ctx)
	if err == nil {
		t.Fatal("should be locked after max failed attempts")
	}

	cycleStr, err := s.GetMeta(ctx, metaUnlockCycle)
	if err != nil {
		t.Fatalf("GetMeta unlock_cycle: %v", err)
	}
	if cycleStr != "1" {
		t.Fatalf("unlock_cycle = %q, want %q", cycleStr, "1")
	}
}

func TestAddTag_IsTransactional(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "KEY", []byte("val"), nil)

	if err := v.AddTag(ctx, "KEY", "aws"); err != nil {
		t.Fatalf("AddTag: %v", err)
	}
	if err := v.AddTag(ctx, "KEY", "prod"); err != nil {
		t.Fatalf("AddTag: %v", err)
	}

	sec, err := v.GetSecret(ctx, "KEY")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if len(sec.Tags) != 2 {
		t.Fatalf("tags = %v, want 2 tags", sec.Tags)
	}
	if string(sec.Value) != "val" {
		t.Fatalf("value changed after AddTag: %q", string(sec.Value))
	}

	err = v.AddTag(ctx, "KEY", "aws")
	if err != nil {
		t.Fatalf("duplicate AddTag: %v", err)
	}

	sec, _ = v.GetSecret(ctx, "KEY")
	if len(sec.Tags) != 2 {
		t.Fatalf("duplicate AddTag should be idempotent, tags = %v", sec.Tags)
	}
}

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

func TestReadKDFVersion_RejectsCorruptedVersion(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()
	ctx := context.Background()

	enc := crypto.NewAESGCM()
	rightKey, _ := enc.GenerateKey()
	kp := &testKeyProvider{enc: enc, key: rightKey}

	s.SetMeta(ctx, "kdf_version", "abc")

	v := New(enc, kp, s)
	defer v.Close()

	err = v.Unlock(ctx)
	if err == nil {
		t.Fatal("Unlock should fail with corrupted KDF version")
	}
	if !strings.Contains(err.Error(), "corrupted kdf_version") {
		t.Fatalf("expected corrupted kdf_version error, got: %v", err)
	}
}

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

func TestUnlock_FailedAttemptsIncrement(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()
	ctx := context.Background()

	enc := crypto.NewAESGCM()
	rightKey, _ := enc.GenerateKey()
	rightKp := &testKeyProvider{enc: enc, key: rightKey}

	v := New(enc, rightKp, s)
	v.key = rightKey
	v.SetSecret(ctx, "TEST", []byte("verify"), nil)
	v.key = nil

	wrongKey, _ := enc.GenerateKey()
	wrongKey[0] ^= 0xFF
	wrongKp := &testKeyProvider{enc: enc, key: wrongKey}

	wrongV := New(enc, wrongKp, s)
	defer wrongV.Close()

	for range 3 {
		wrongV.Unlock(ctx)
	}

	attempts, _ := s.GetMeta(ctx, metaUnlockAttempts)
	if attempts != "3" {
		t.Fatalf("unlock_attempts = %q, want %q", attempts, "3")
	}
}

func TestUnlock_LockDurationExponential(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()
	ctx := context.Background()

	enc := crypto.NewAESGCM()
	rightKey, _ := enc.GenerateKey()
	rightKp := &testKeyProvider{enc: enc, key: rightKey}

	v := New(enc, rightKp, s)
	v.key = rightKey
	v.SetSecret(ctx, "TEST", []byte("verify"), nil)
	v.key = nil

	wrongKey, _ := enc.GenerateKey()
	wrongKey[0] ^= 0xFF
	wrongKp := &testKeyProvider{enc: enc, key: wrongKey}

	wrongV := New(enc, wrongKp, s)
	defer wrongV.Close()

	for range maxUnlockAttempts {
		wrongV.Unlock(ctx)
	}

	lockedUntil1, _ := s.GetMeta(ctx, metaUnlockLockedUntil)
	if lockedUntil1 == "" {
		t.Fatal("expected lock after first cycle")
	}

	cycleAfterFirst, _ := s.GetMeta(ctx, metaUnlockCycle)
	if cycleAfterFirst != "1" {
		t.Fatalf("unlock_cycle after first cycle = %q, want %q", cycleAfterFirst, "1")
	}

	s.SetMeta(ctx, metaUnlockLockedUntil, "")
	s.SetMeta(ctx, metaUnlockAttempts, "0")

	for range maxUnlockAttempts {
		wrongV.Unlock(ctx)
	}

	cycleStr, _ := s.GetMeta(ctx, metaUnlockCycle)
	if cycleStr != "2" {
		t.Fatalf("unlock_cycle = %q after 2 full cycles, want %q", cycleStr, "2")
	}

	lockedUntil2, _ := s.GetMeta(ctx, metaUnlockLockedUntil)
	if lockedUntil2 == "" {
		t.Fatal("expected lock after second cycle")
	}

	ts1, _ := time.Parse(time.RFC3339, lockedUntil1)
	ts2, _ := time.Parse(time.RFC3339, lockedUntil2)
	expected1 := time.Duration(unlockDelayBaseMs) * time.Millisecond
	expected2 := time.Duration(unlockDelayBaseMs) * 2 * time.Millisecond
	tolerance := 2 * time.Second

	if ts1.Before(time.Now().Add(expected1).Add(-tolerance)) || ts1.After(time.Now().Add(expected1).Add(tolerance)) {
		t.Fatalf("first lock timestamp not within expected range for base duration %v", expected1)
	}
	if ts2.Before(time.Now().Add(expected2).Add(-tolerance)) || ts2.After(time.Now().Add(expected2).Add(tolerance)) {
		t.Fatalf("second lock timestamp not within expected range for double duration %v", expected2)
	}
}

func TestUnlock_SuccessResetsState(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	enc := crypto.NewAESGCM()

	rightKey, err := enc.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	rightKp := &testKeyProvider{enc: enc, key: rightKey}

	ctx := context.Background()
	if err = InitVault(ctx, dbPath, enc, rightKp, InitOptions{SkipKeychain: true}); err != nil {
		t.Fatal(err)
	}

	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	rightV := New(enc, rightKp, s)
	if err = rightV.Unlock(ctx); err != nil {
		t.Fatalf("initial unlock: %v", err)
	}
	rightV.SetSecret(ctx, "TEST", []byte("verify"), nil)
	rightV.key = nil

	wrongKey, _ := enc.GenerateKey()
	wrongKey[0] ^= 0xFF
	wrongKp := &testKeyProvider{enc: enc, key: wrongKey}
	wrongV := New(enc, wrongKp, s)

	for range 5 {
		wrongV.Unlock(ctx)
	}

	attemptsBefore, _ := s.GetMeta(ctx, metaUnlockAttempts)
	if attemptsBefore == "0" {
		t.Fatal("expected non-zero attempts before successful unlock")
	}

	s2, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	rightV2 := New(enc, rightKp, s2)
	defer rightV2.Close()

	err = rightV2.Unlock(ctx)
	if err != nil {
		t.Fatalf("Unlock with correct key: %v", err)
	}

	attempts, _ := s2.GetMeta(ctx, metaUnlockAttempts)
	if attempts != "0" {
		t.Fatalf("unlock_attempts = %q after successful unlock, want %q", attempts, "0")
	}

	lockedUntil, _ := s2.GetMeta(ctx, metaUnlockLockedUntil)
	if lockedUntil != "" {
		t.Fatalf("unlock_locked_until = %q after successful unlock, want empty", lockedUntil)
	}

	cycle, _ := s2.GetMeta(ctx, metaUnlockCycle)
	if cycle != "0" {
		t.Fatalf("unlock_cycle = %q after successful unlock, want %q", cycle, "0")
	}
}

func TestUnlock_LockedVaultReturnsTimestamp(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()
	ctx := context.Background()

	enc := crypto.NewAESGCM()
	rightKey, _ := enc.GenerateKey()
	rightKp := &testKeyProvider{enc: enc, key: rightKey}

	v := New(enc, rightKp, s)
	v.key = rightKey
	v.SetSecret(ctx, "TEST", []byte("verify"), nil)
	v.key = nil

	wrongKey, _ := enc.GenerateKey()
	wrongKey[0] ^= 0xFF
	wrongKp := &testKeyProvider{enc: enc, key: wrongKey}

	wrongV := New(enc, wrongKp, s)
	defer wrongV.Close()

	for range maxUnlockAttempts {
		wrongV.Unlock(ctx)
	}

	lockedUntil, _ := s.GetMeta(ctx, metaUnlockLockedUntil)
	if lockedUntil == "" {
		t.Fatal("expected locked_until to be set after max failed attempts")
	}
	if _, parseErr := time.Parse(time.RFC3339, lockedUntil); parseErr != nil {
		t.Fatalf("invalid locked_until timestamp: %v", parseErr)
	}

	s.SetMeta(ctx, metaUnlockLockedUntil, time.Now().Add(1*time.Hour).Format(time.RFC3339))

	err = wrongV.Unlock(ctx)
	if err == nil {
		t.Fatal("should be locked")
	}
	if !strings.Contains(err.Error(), "locked until") {
		t.Fatalf("expected 'locked until' in error, got: %v", err)
	}
}

func TestRemoveTag_NonExistentTag(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "KEY", []byte("val"), []string{"aws", "prod"})

	err := v.RemoveTag(ctx, "KEY", "nonexistent")
	if err != nil {
		t.Fatalf("removing non-existent tag should not error: %v", err)
	}

	sec, _ := v.GetSecret(ctx, "KEY")
	if len(sec.Tags) != 2 {
		t.Fatalf("tags = %v, want 2 tags unchanged", sec.Tags)
	}
}

func TestGetSecretsByTags_MultipleOR(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "A", []byte("val_a"), []string{"aws"})
	v.SetSecret(ctx, "B", []byte("val_b"), []string{"stripe"})
	v.SetSecret(ctx, "C", []byte("val_c"), []string{"prod"})
	v.SetSecret(ctx, "D", []byte("val_d"), []string{"gcp"})

	result, err := v.GetSecretsByTags(ctx, []string{"aws", "stripe"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 results for OR filter, got %d", len(result))
	}

	names := make(map[string]bool)
	for _, r := range result {
		names[r.Name] = true
	}
	if !names["A"] || !names["B"] {
		t.Fatalf("expected A and B, got %v", names)
	}
}

func TestGetSecretsByTags_NoMatches(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "A", []byte("val_a"), []string{"aws"})
	v.SetSecret(ctx, "B", []byte("val_b"), []string{"stripe"})

	result, err := v.GetSecretsByTags(ctx, []string{"nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 results, got %d", len(result))
	}
}

func TestTagsPreservedAfterRollback(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()
	ctx := context.Background()

	v.SetSecret(ctx, "KEY", []byte("v1"), []string{"aws", "prod"})
	v.SetSecret(ctx, "KEY", []byte("v2"), []string{"stripe"})

	err := v.Rollback(ctx, "KEY", 1)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	sec, err := v.GetSecret(ctx, "KEY")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(sec.Value) != "v1" {
		t.Fatalf("value = %q, want %q", string(sec.Value), "v1")
	}
	if len(sec.Tags) != 2 {
		t.Fatalf("tags after rollback = %v, want 2 tags", sec.Tags)
	}
	tagSet := make(map[string]bool)
	for _, tag := range sec.Tags {
		tagSet[tag] = true
	}
	if !tagSet["aws"] || !tagSet["prod"] {
		t.Fatalf("expected aws+prod tags, got %v", sec.Tags)
	}
}

func TestV1Vault_WarnsButAllows(t *testing.T) {
	v := setupTestVaultV1(t)
	defer v.Close()
	ctx := context.Background()

	if err := v.SetSecret(ctx, "TEST", []byte("value"), nil); err != nil {
		t.Fatal(err)
	}

	v.mu.Lock()
	v.v1KDF = true
	v.mu.Unlock()

	sec, err := v.GetSecret(ctx, "TEST")
	if err != nil {
		t.Fatalf("GetSecret on V1 vault should work: %v", err)
	}
	if string(sec.Value) != "value" {
		t.Fatalf("expected 'value', got %q", string(sec.Value))
	}

	all, err := v.GetAllSecrets(ctx)
	if err != nil {
		t.Fatalf("GetAllSecrets on V1 vault should work: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("GetAllSecrets should return secrets")
	}
}

func TestUnlock_EmptyLegacyVaultRejected(t *testing.T) {
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
	s.SetMeta(ctx, "verify_data", "")
	s.SetMeta(ctx, "verify_iv", "")
	s.Close()

	s2, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	v := New(enc, kp, s2)
	defer v.Close()

	err = v.Unlock(ctx)
	if err == nil {
		t.Fatal("empty legacy vault should reject unlock")
	}
	if !strings.Contains(err.Error(), "integrity check") {
		t.Fatalf("expected integrity check error, got: %v", err)
	}

	if v.key != nil {
		t.Fatal("v.key must remain nil after integrity check failure")
	}
}

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
		v.SetSecret(ctx, "KEY", fmt.Appendf(nil, "v%d", i), nil)
	}
	<-done
}

func newTestGitVault(t *testing.T) *Vault {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	s, err := store.NewGitStore(repo, store.GitOptions{})
	if err != nil {
		t.Fatalf("git store: %v", err)
	}
	if err = s.InitSchema(); err != nil {
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
	ctx := context.Background()
	if err := v.Unlock(ctx); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := v.SetSecret(ctx, "KEY", []byte("secret123"), []string{"prod"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := v.GetSecret(ctx, "KEY")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.Value) != "secret123" {
		t.Fatalf("value = %q", got.Value)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "prod" {
		t.Fatalf("tags = %v", got.Tags)
	}
	all, err := v.GetAllSecrets(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("all: %v %v", all, err)
	}
}

func TestVaultGitAADActuallyBinds(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	ctx := context.Background()
	_ = v.Unlock(ctx)
	_ = v.SetSecret(ctx, "KEY", []byte("secret123"), nil)
	salt, _ := v.store.GetMeta(ctx, "kdf_salt")
	if salt == "" {
		t.Fatal("salt")
	}
	forgedKey, err := v.enc.DeriveKeyFromPassword(
		"test-password",
		[]byte("othersalt-16byte"),
		crypto.DefaultKDFParams(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := v.store.GetSecret(ctx, "KEY")
	if _, err = v.enc.DecryptWithAAD(stored.EncryptedValue, stored.IV, forgedKey,
		[]byte("psst:v1:argon2id:"+salt)); err == nil {
		t.Fatal("wrong key must fail via AAD+GCM")
	}
}

func TestVaultRetagSecret(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	ctx := context.Background()
	_ = v.Unlock(ctx)
	_ = v.SetSecret(ctx, "KEY", []byte("secret123"), []string{"prod"})
	if err := v.RetagSecret(ctx, "KEY", []string{"test"}); err != nil {
		t.Fatalf("retag: %v", err)
	}
	got, _ := v.GetSecret(ctx, "KEY")
	if got.Tags[0] != "test" {
		t.Fatalf("tag = %v", got.Tags)
	}
	if err := v.RetagSecret(ctx, "KEY", nil); err != nil {
		t.Fatalf("untag: %v", err)
	}
	got, _ = v.GetSecret(ctx, "KEY")
	if len(got.Tags) != 0 {
		t.Fatalf("tags after untag = %v", got.Tags)
	}
}

func TestVaultRollbackReencrypts(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	ctx := context.Background()
	_ = v.Unlock(ctx)
	_ = v.SetSecret(ctx, "KEY", []byte("v1"), nil)
	_ = v.SetSecret(ctx, "KEY", []byte("v2"), nil)
	if err := v.Rollback(ctx, "KEY", 1); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	got, _ := v.GetSecret(ctx, "KEY")
	if string(got.Value) != "v1" {
		t.Fatalf("value = %q, want v1", got.Value)
	}
}

func TestVaultListSecretsMapsUpdatedBy(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	ctx := context.Background()
	if err := v.Unlock(ctx); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := v.SetSecret(ctx, "KEY", []byte("secret123"), nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	metas, err := v.ListSecrets(ctx)
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
	ctx := context.Background()
	_ = v.Unlock(ctx)
	err := v.Batch(func() error {
		for _, n := range []string{"A1", "B2"} {
			if err := v.SetSecret(ctx, n, []byte("x"), nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	metas, _ := v.ListSecrets(ctx)
	if len(metas) != 2 {
		t.Fatalf("metas = %d", len(metas))
	}
}

func newBareRemoteVault(t *testing.T) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", "-b", "main", remote).CombinedOutput(); err != nil {
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
	if err = g.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	return g, repo
}

func vaultFromPassword(t *testing.T, gs *store.GitStore, password string) *Vault {
	t.Helper()
	enc := crypto.NewAESGCM()
	v := New(enc, keyring.NewPasswordProvider(enc, false), gs)
	t.Setenv("PSST_PASSWORD", password)
	if err := v.Unlock(context.Background()); err != nil {
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
	if err = gs.InitSchema(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v := vaultFromPassword(t, gs, "test-password")
	if err = v.SetSecret(ctx, "API_KEY", []byte("secret123"), []string{"prod"}); err != nil {
		t.Fatal(err)
	}
	if err = v.SetSecret(ctx, "DB_PASS", []byte("test-password"), nil); err != nil {
		t.Fatal(err)
	}
	oldSalt, _ := gs.GetMeta(ctx, "kdf_salt")
	oldTime, _ := gs.GetMeta(ctx, "kdf_time")
	oldMemory, _ := gs.GetMeta(ctx, "kdf_memory")

	n, err := v.Rotate(ctx, "new-password", nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n != 2 {
		t.Fatalf("rotated = %d, want 2", n)
	}
	newSalt, _ := gs.GetMeta(ctx, "kdf_salt")
	if newSalt == oldSalt || newSalt == "" {
		t.Fatalf("salt unchanged: %q", newSalt)
	}
	newTime, _ := gs.GetMeta(ctx, "kdf_time")
	newMemory, _ := gs.GetMeta(ctx, "kdf_memory")
	if newTime != oldTime || newMemory != oldMemory {
		t.Fatalf("params changed: %s/%s was %s/%s", newTime, newMemory, oldTime, oldMemory)
	}
	out, _ := store.NewGitRunner(repo).Run("log", "--format=%s", "-2")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 || lines[0] != "psst: rotate" {
		t.Fatalf("log = %q", out)
	}
	got, err := v.GetSecret(ctx, "API_KEY")
	if err != nil || string(got.Value) != "secret123" || got.Tags[0] != "prod" {
		t.Fatalf("roundtrip = %q %v", got.Value, err)
	}
	if err = v.SetSecret(ctx, "AFTER", []byte("x"), nil); err != nil {
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
	ctx := context.Background()
	v := vaultFromPassword(t, gs, "test-password")
	if err := v.SetSecret(ctx, "API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Rotate(ctx, "new-password", nil); err != nil {
		t.Fatal(err)
	}
	old := vaultFromPassword(t, gs, "test-password")
	if _, err := old.GetSecret(ctx, "API_KEY"); err == nil {
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
	ctx := context.Background()
	v := vaultFromPassword(t, gs, "test-password")
	if err := v.SetSecret(ctx, "API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatal(err)
	}
	other, err := store.CloneGitVault(remote, filepath.Join(t.TempDir(), "repo2"), store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatal(err)
	}
	if err = other.InitSchema(); err != nil {
		t.Fatal(err)
	}
	if err = v.VerifyAllDecryptable(ctx); err != nil {
		t.Fatal(err)
	}
	ov := vaultFromPassword(t, other, "test-password")
	if err = ov.SetSecret(ctx, "LATE", []byte("late-secret456"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err = v.Rotate(ctx, "new-password", nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	got, err := v.GetSecret(ctx, "LATE")
	if err != nil || string(got.Value) != "late-secret456" {
		t.Fatalf("late arrival not rotated: %q %v", got.Value, err)
	}
}

func TestVaultRotateAbortsOnUndecryptable(t *testing.T) {
	g, repo := newGitVaultStore(t)
	ctx := context.Background()
	iv := make([]byte, 12)
	if err := g.SetSecret(ctx, "BAD", []byte("garbage-not-base64!"), iv, nil); err != nil {
		t.Fatal(err)
	}
	v := vaultFromPassword(t, g, "test-password")
	saltBefore, _ := g.GetMeta(ctx, "kdf_salt")
	logBefore, _ := store.NewGitRunner(repo).Run("log", "--format=%H")
	if err := v.VerifyAllDecryptable(ctx); err == nil {
		t.Fatal("pre-flight must fail on garbage")
	}
	if _, err := v.Rotate(ctx, "new-password", nil); err == nil {
		t.Fatal("rotate must abort")
	}
	salt, _ := g.GetMeta(ctx, "kdf_salt")
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
	ctx := context.Background()
	v := vaultFromPassword(t, g, "test-password")
	n, err := v.Rotate(ctx, "new-password", nil)
	if err != nil || n != 0 {
		t.Fatalf("empty rotate = %d %v", n, err)
	}
	if err = v.SetSecret(ctx, "FIRST", []byte("x"), nil); err != nil {
		t.Fatalf("write after empty rotate: %v", err)
	}
}

func readVaultMetaFile(t *testing.T, repo string) *store.VaultMeta {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, "psst.yaml"))
	if err != nil {
		t.Fatalf("read psst.yaml: %v", err)
	}
	meta, err := store.ParseVaultMeta(data)
	if err != nil {
		t.Fatalf("parse psst.yaml: %v", err)
	}
	return meta
}

func TestVaultRotateKDFStrengthens(t *testing.T) {
	remote := newBareRemoteVault(t)
	repo := filepath.Join(t.TempDir(), "repo")
	gs, err := store.NewGitStore(repo, store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatal(err)
	}
	if err = gs.InitSchema(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v := vaultFromPassword(t, gs, "test-password")
	if err = v.SetSecret(ctx, "API_KEY", []byte("secret123"), []string{"prod"}); err != nil {
		t.Fatal(err)
	}

	stronger := kdf.Params{Time: 4, Memory: 64 * 1024, Threads: 4}
	n, err := v.Rotate(ctx, "new-password", &stronger)
	if err != nil {
		t.Fatalf("rotate with stronger params: %v", err)
	}
	if n != 1 {
		t.Fatalf("rotated = %d, want 1", n)
	}

	meta := readVaultMetaFile(t, repo)
	if meta.Params.Time != 4 {
		t.Fatalf("kdf_time = %d, want 4", meta.Params.Time)
	}
	if meta.Params != stronger {
		t.Fatalf("params = %+v, want %+v", meta.Params, stronger)
	}

	out, _ := store.NewGitRunner(repo).Run("log", "--format=%s", "-3")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 || lines[0] != "psst: rotate" {
		t.Fatalf("log = %q", out)
	}

	got, err := v.GetSecret(ctx, "API_KEY")
	if err != nil || string(got.Value) != "secret123" || got.Tags[0] != "prod" {
		t.Fatalf("roundtrip = %q %v", got.Value, err)
	}
	if err = v.SetSecret(ctx, "AFTER", []byte("x"), nil); err != nil {
		t.Fatalf("same-process write: %v", err)
	}

	cloned, err := store.CloneGitVault(remote, filepath.Join(t.TempDir(), "repo2"), store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if _, err = cloned.SyncAcceptRotation(context.Background()); err != nil {
		t.Fatalf("accept on second clone: %v", err)
	}
	cv := vaultFromPassword(t, cloned, "new-password")
	cgot, err := cv.GetSecret(ctx, "API_KEY")
	if err != nil || string(cgot.Value) != "secret123" {
		t.Fatalf("second clone roundtrip = %q %v", cgot.Value, err)
	}
}

func TestVaultRotateKDFWeakeningFails(t *testing.T) {
	g, repo := newGitVaultStore(t)
	ctx := context.Background()
	v := vaultFromPassword(t, g, "test-password")
	if err := v.SetSecret(ctx, "API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatal(err)
	}

	stronger := kdf.Params{Time: 4, Memory: 64 * 1024, Threads: 4}
	if _, err := v.Rotate(ctx, "mid-password", &stronger); err != nil {
		t.Fatalf("strengthen: %v", err)
	}

	saltBefore, _ := g.GetMeta(ctx, "kdf_salt")
	logBefore, _ := store.NewGitRunner(repo).Run("log", "--format=%H")

	weaker := kdf.Params{Time: 3, Memory: 64 * 1024, Threads: 4}
	_, err := v.Rotate(ctx, "new-password", &weaker)
	if err == nil || !strings.Contains(err.Error(), "rotation must not weaken KDF parameters") {
		t.Fatalf("weakening error = %v", err)
	}

	saltAfter, _ := g.GetMeta(ctx, "kdf_salt")
	if saltAfter != saltBefore {
		t.Fatalf("salt changed on weakening abort: %q was %q", saltAfter, saltBefore)
	}
	logAfter, _ := store.NewGitRunner(repo).Run("log", "--format=%H")
	if logAfter != logBefore {
		t.Fatal("commits landed on weakening abort")
	}
	if got, _ := g.GetMeta(ctx, "kdf_time"); got != "4" {
		t.Fatalf("kdf_time = %q, want 4", got)
	}
	got, err := v.GetSecret(ctx, "API_KEY")
	if err != nil || string(got.Value) != "secret123" {
		t.Fatalf("vault still readable = %q %v", got.Value, err)
	}
}

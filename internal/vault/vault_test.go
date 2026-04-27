package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/crypto"
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

	v1Key, err := enc.KeyToBuffer(hex.EncodeToString(rawKey))
	if err != nil {
		t.Fatal(err)
	}
	v.key = v1Key

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
		v2Key, deriveErr = v.enc.KeyToBufferV2WithSalt(rawKeyHex, salt)
	} else {
		v2Key, deriveErr = v.enc.KeyToBufferV2(rawKeyHex)
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

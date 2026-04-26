package vault

import (
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

func TestMigrateKDF_UpdatesKey(t *testing.T) {
	v := setupTestVaultV1(t)
	defer v.Close()

	if err := v.SetSecret("API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatal(err)
	}

	if err := v.MigrateKDF(); err != nil {
		t.Fatalf("MigrateKDF: %v", err)
	}

	sec, err := v.GetSecret("API_KEY")
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

	for i := range 15 {
		if err := v.SetSecret("KEY", fmt.Appendf(nil, "v%d", i), nil); err != nil {
			t.Fatalf("SetSecret iteration %d: %v", i, err)
		}
	}

	sec, err := v.GetSecret("KEY")
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

	if err := v.SetSecret("TEST", []byte("value"), nil); err != nil {
		t.Fatal(err)
	}

	if err := v.MigrateKDF(); err != nil {
		t.Fatal(err)
	}

	saltB64, err := v.store.GetMeta("kdf_salt")
	if err != nil {
		t.Fatal(err)
	}
	if saltB64 == "" {
		t.Fatal("MigrateKDF should generate kdf_salt when migrating from V1")
	}

	sec, err := v.GetSecret("TEST")
	if err != nil {
		t.Fatalf("GetSecret after migrate: %v", err)
	}
	if string(sec.Value) != "value" {
		t.Fatalf("value = %q, want %q", string(sec.Value), "value")
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
	if initErr := InitVault(path2, enc, kp2, InitOptions{SkipKeychain: true}); initErr != nil {
		t.Fatal(initErr)
	}

	s2, storeErr := store.NewSQLite(path2)
	if storeErr != nil {
		t.Fatal(storeErr)
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

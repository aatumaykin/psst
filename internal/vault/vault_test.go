package vault

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/store"
)

type testKeyProvider struct {
	enc *crypto.AESGCM
	key []byte
}

func (t *testKeyProvider) GetKey(service, account string) ([]byte, error) {
	if t.key == nil {
		return nil, fmt.Errorf("no key")
	}
	return t.key, nil
}

func (t *testKeyProvider) SetKey(service, account string, key []byte) error {
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
	if err := s.InitSchema(); err != nil {
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

	if err := v.SetSecret("API_KEY", "secret123", []string{"prod"}); err != nil {
		t.Fatal(err)
	}

	sec, err := v.GetSecret("API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if sec.Value != "secret123" {
		t.Fatalf("value = %q, want %q", sec.Value, "secret123")
	}
	if len(sec.Tags) != 1 || sec.Tags[0] != "prod" {
		t.Fatalf("tags = %v", sec.Tags)
	}
}

func TestListSecrets(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	v.SetSecret("A", "val_a", nil)
	v.SetSecret("B", "val_b", nil)

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

	v.SetSecret("KEY", "val", nil)
	v.DeleteSecret("KEY")

	sec, _ := v.GetSecret("KEY")
	if sec != nil {
		t.Fatal("secret should be nil after delete")
	}
}

func TestHistoryAndRollback(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	v.SetSecret("KEY", "v1", nil)
	v.SetSecret("KEY", "v2", nil)
	v.SetSecret("KEY", "v3", nil)

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
	if sec.Value != "v1" {
		t.Fatalf("after rollback value = %q, want %q", sec.Value, "v1")
	}
}

func TestTags(t *testing.T) {
	v := setupTestVault(t)
	defer v.Close()

	v.SetSecret("KEY", "val", nil)
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

	v.SetSecret("A", "val_a", []string{"aws", "prod"})
	v.SetSecret("B", "val_b", []string{"stripe"})
	v.SetSecret("C", "val_c", []string{"prod"})

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

	v.SetSecret("A", "val_a", nil)
	v.SetSecret("B", "val_b", nil)

	all, err := v.GetAllSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if all["A"] != "val_a" || all["B"] != "val_b" {
		t.Fatalf("all = %v", all)
	}
}

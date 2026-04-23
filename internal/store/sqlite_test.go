package store

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	s, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSetAndGetSecret(t *testing.T) {
	s := setupTestStore(t)

	err := s.SetSecret("API_KEY", []byte("encrypted"), []byte("iv1234567890"), []string{"prod"})
	if err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	sec, err := s.GetSecret("API_KEY")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if sec == nil {
		t.Fatal("secret should exist")
	}
	if sec.Name != "API_KEY" {
		t.Fatalf("name = %q, want %q", sec.Name, "API_KEY")
	}
	if string(sec.EncryptedValue) != "encrypted" {
		t.Fatalf("encrypted_value = %q", sec.EncryptedValue)
	}
	if len(sec.Tags) != 1 || sec.Tags[0] != "prod" {
		t.Fatalf("tags = %v", sec.Tags)
	}
}

func TestGetSecretNotFound(t *testing.T) {
	s := setupTestStore(t)
	sec, err := s.GetSecret("NOPE")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if sec != nil {
		t.Fatal("should be nil for missing secret")
	}
}

func TestDeleteSecret(t *testing.T) {
	s := setupTestStore(t)
	s.SetSecret("KEY", []byte("enc"), []byte("iv"), nil)
	s.DeleteSecret("KEY")
	sec, _ := s.GetSecret("KEY")
	if sec != nil {
		t.Fatal("secret should be deleted")
	}
}

func TestListSecrets(t *testing.T) {
	s := setupTestStore(t)
	s.SetSecret("A", []byte("a"), []byte("iv"), nil)
	s.SetSecret("B", []byte("b"), []byte("iv"), []string{"test"})

	list, err := s.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].Name != "A" {
		t.Fatalf("first = %q, want A", list[0].Name)
	}
}

func TestHistoryAndRollback(t *testing.T) {
	s := setupTestStore(t)
	s.SetSecret("KEY", []byte("v1"), []byte("iv1"), nil)
	s.AddHistory("KEY", 1, []byte("v1"), []byte("iv1"), nil)
	s.SetSecret("KEY", []byte("v2"), []byte("iv2"), nil)
	s.AddHistory("KEY", 2, []byte("v2"), []byte("iv2"), nil)

	history, err := s.GetHistory("KEY")
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history len = %d, want 2", len(history))
	}
	if history[0].Version != 2 {
		t.Fatalf("first version = %d, want 2 (DESC)", history[0].Version)
	}
}

func TestDeleteHistory(t *testing.T) {
	s := setupTestStore(t)
	s.SetSecret("KEY", []byte("v"), []byte("iv"), nil)
	s.AddHistory("KEY", 1, []byte("v"), []byte("iv"), nil)
	s.DeleteHistory("KEY")
	history, _ := s.GetHistory("KEY")
	if len(history) != 0 {
		t.Fatalf("history should be empty after delete, got %d", len(history))
	}
}

func TestPruneHistory(t *testing.T) {
	s := setupTestStore(t)
	for i := 1; i <= 15; i++ {
		s.AddHistory("KEY", i, []byte("v"), []byte("iv"), nil)
	}
	s.PruneHistory("KEY", 10)
	history, _ := s.GetHistory("KEY")
	if len(history) > 10 {
		t.Fatalf("history should be <= 10 after prune, got %d", len(history))
	}
}

func TestVaultFileCreated(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	s, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.InitSchema()
	s.Close()
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("vault.db should be created")
	}
}

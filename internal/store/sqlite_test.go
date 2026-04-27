package store

import (
	"context"
	"errors"
	"fmt"
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
	if initErr := s.InitSchema(); initErr != nil {
		t.Fatalf("InitSchema: %v", initErr)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSetAndGetSecret(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	err := s.SetSecret(ctx, "API_KEY", []byte("encrypted"), []byte("iv1234567890"), []string{"prod"})
	if err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	sec, err := s.GetSecret(ctx, "API_KEY")
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
	ctx := context.Background()
	sec, err := s.GetSecret(ctx, "NOPE")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if sec != nil {
		t.Fatal("should be nil for missing secret")
	}
}

func TestDeleteSecret(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	s.SetSecret(ctx, "KEY", []byte("enc"), []byte("iv"), nil)
	s.DeleteSecret(ctx, "KEY")
	sec, _ := s.GetSecret(ctx, "KEY")
	if sec != nil {
		t.Fatal("secret should be deleted")
	}
}

func TestListSecrets(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	s.SetSecret(ctx, "A", []byte("a"), []byte("iv"), nil)
	s.SetSecret(ctx, "B", []byte("b"), []byte("iv"), []string{"test"})

	list, err := s.ListSecrets(ctx)
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
	ctx := context.Background()
	s.SetSecret(ctx, "KEY", []byte("v1"), []byte("iv1"), nil)
	s.AddHistory(ctx, "KEY", 1, []byte("v1"), []byte("iv1"), nil)
	s.SetSecret(ctx, "KEY", []byte("v2"), []byte("iv2"), nil)
	s.AddHistory(ctx, "KEY", 2, []byte("v2"), []byte("iv2"), nil)

	history, err := s.GetHistory(ctx, "KEY")
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
	ctx := context.Background()
	s.SetSecret(ctx, "KEY", []byte("v"), []byte("iv"), nil)
	s.AddHistory(ctx, "KEY", 1, []byte("v"), []byte("iv"), nil)
	s.DeleteHistory(ctx, "KEY")
	history, _ := s.GetHistory(ctx, "KEY")
	if len(history) != 0 {
		t.Fatalf("history should be empty after delete, got %d", len(history))
	}
}

func TestPruneHistory(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()
	for i := 1; i <= 15; i++ {
		s.AddHistory(ctx, "KEY", i, []byte("v"), []byte("iv"), nil)
	}
	s.PruneHistory(ctx, "KEY", 10)
	history, _ := s.GetHistory(ctx, "KEY")
	if len(history) > 10 {
		t.Fatalf("history should be <= 10 after prune, got %d", len(history))
	}
}

func TestNewSQLite_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	s, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("NewSQLite failed: %v", err)
	}
	s.InitSchema()
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

func TestGetAllSecrets(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	s.SetSecret(ctx, "A", []byte("encA"), []byte("ivA"), []string{"tag1"})
	s.SetSecret(ctx, "B", []byte("encB"), []byte("ivB"), nil)

	all, err := s.GetAllSecrets(ctx)
	if err != nil {
		t.Fatalf("GetAllSecrets failed: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("len = %d, want 2", len(all))
	}
}

func TestExecTx_Commit(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	err := s.ExecTx(func() error {
		return s.SetSecret(ctx, "TX", []byte("enc"), []byte("iv"), nil)
	})
	if err != nil {
		t.Fatalf("ExecTx failed: %v", err)
	}

	sec, _ := s.GetSecret(ctx, "TX")
	if sec == nil {
		t.Fatal("secret should exist after commit")
	}
}

func TestExecTx_Rollback(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	err := s.ExecTx(func() error {
		s.SetSecret(ctx, "TX", []byte("enc"), []byte("iv"), nil)
		return errors.New("intentional error")
	})
	if err == nil {
		t.Fatal("ExecTx should return error")
	}

	sec, _ := s.GetSecret(ctx, "TX")
	if sec != nil {
		t.Fatal("secret should not exist after rollback")
	}
}

func TestSetSecret_Upsert(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	s.SetSecret(ctx, "K", []byte("enc1"), []byte("iv1"), nil)
	s.SetSecret(ctx, "K", []byte("enc2"), []byte("iv2"), []string{"t"})

	sec, _ := s.GetSecret(ctx, "K")
	if sec == nil {
		t.Fatal("secret should exist")
	}
	if string(sec.EncryptedValue) != "enc2" {
		t.Fatalf("value = %q, want %q", sec.EncryptedValue, "enc2")
	}
}

func TestMeta(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	val, err := s.GetMeta(ctx, "kdf_version")
	if err != nil {
		t.Fatalf("GetMeta failed: %v", err)
	}
	if val != "" {
		t.Fatalf("expected empty, got %q", val)
	}

	if setErr := s.SetMeta(ctx, "kdf_version", "2"); setErr != nil {
		t.Fatalf("SetMeta failed: %v", setErr)
	}

	val, _ = s.GetMeta(ctx, "kdf_version")
	if val != "2" {
		t.Fatalf("expected '2', got %q", val)
	}
}

func TestExecTx_DataRace(t *testing.T) {
	s := setupTestStore(t)
	ctx := context.Background()

	s.SetSecret(ctx, "KEY", []byte("v"), []byte("iv"), nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			s.GetSecret(ctx, "KEY")
		}
	}()

	for i := range 100 {
		s.ExecTx(func() error {
			return s.SetSecret(ctx, "KEY", fmt.Appendf(nil, "v%d", i), []byte("iv"), nil)
		})
	}
	<-done
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
	if _, statErr := os.Stat(dbPath); os.IsNotExist(statErr) {
		t.Fatal("vault.db should be created")
	}
}

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

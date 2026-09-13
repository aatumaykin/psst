package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/store"
)

func TestEnsureRemoteEmptyRefusesVault(t *testing.T) {
	remote := filepath.Join(t.TempDir(), "remote.git")
	seed, err := store.NewGitStore(remote, store.GitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.InitSchema(); err != nil {
		t.Fatal(err)
	}
	_ = seed.Close()

	repoPath := filepath.Join(t.TempDir(), "env", "repo")
	gs, err := store.CloneGitVault(remote, repoPath, store.GitOptions{})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	_ = gs.Close()

	err = ensureRemoteEmpty(repoPath)
	if err == nil {
		t.Fatal("migrate into non-empty remote must be refused")
	}
	if !strings.Contains(err.Error(), "remote is not an empty vault") {
		t.Fatalf("message = %v", err)
	}
}

func TestEnsureRemoteEmptyAllowsFreshRemote(t *testing.T) {
	dir := t.TempDir()
	remote := filepath.Join(dir, "empty.git")
	if _, err := store.NewGitRunner(dir).Run("init", "--bare", "-b", "main", remote); err != nil {
		t.Fatalf("init remote: %v", err)
	}

	repoPath := filepath.Join(t.TempDir(), "env", "repo")
	gs, err := store.CloneGitVault(remote, repoPath, store.GitOptions{})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	_ = gs.Close()

	if err := ensureRemoteEmpty(repoPath); err != nil {
		t.Fatalf("fresh remote must pass: %v", err)
	}
}

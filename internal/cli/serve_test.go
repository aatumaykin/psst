package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/store"
)

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{
		"127.0.0.1": true, "localhost": true, "::1": true, "[::1]": true,
		"0.0.0.0": false, "example.com": false, "192.168.1.5": false, "": false,
	} {
		if got := isLoopbackHost(h); got != want {
			t.Fatalf("isLoopbackHost(%q) = %v", h, got)
		}
	}
}

func TestResolveServeToken(t *testing.T) {
	t.Setenv("PSST_SERVE_TOKEN", "")
	tok, generated, err := resolveServeToken("flag-token")
	if err != nil || tok != "flag-token" || generated {
		t.Fatalf("flag precedence: %q %v %v", tok, generated, err)
	}
	t.Setenv("PSST_SERVE_TOKEN", "env-token")
	tok, generated, err = resolveServeToken("")
	if err != nil || tok != "env-token" || generated {
		t.Fatalf("env precedence: %q %v %v", tok, generated, err)
	}
	t.Setenv("PSST_SERVE_TOKEN", "")
	tok, generated, err = resolveServeToken("")
	if err != nil || len(tok) != 43 || !generated {
		t.Fatalf("generated: len=%d generated=%v err=%v", len(tok), generated, err)
	}
	tok2, _, err := resolveServeToken("")
	if err != nil || tok == tok2 {
		t.Fatal("tokens must be random")
	}
}

func TestServeRequiresGitStorage(t *testing.T) {
	envDir := filepath.Join(t.TempDir(), "env")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(envDir, "vault.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := serveStorageGate(envDir, "")
	if err == nil {
		t.Fatal("sqlite vault must be rejected")
	}
	if !strings.Contains(err.Error(), "migrate storage") {
		t.Fatalf("message = %v", err)
	}
}

func TestServeMissingVault(t *testing.T) {
	envDir := filepath.Join(t.TempDir(), "env")
	err := serveStorageGate(envDir, "")
	if !errors.Is(err, errNoVault) {
		t.Fatalf("missing vault = %v", err)
	}
}

func TestServeGitVaultPassesGate(t *testing.T) {
	envDir := filepath.Join(t.TempDir(), "env")
	repo := filepath.Join(envDir, "repo")
	gs, err := store.NewGitStore(repo, store.GitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = gs.InitSchema(); err != nil {
		t.Fatal(err)
	}
	if err = serveStorageGate(envDir, ""); err != nil {
		t.Fatalf("git vault rejected: %v", err)
	}
}

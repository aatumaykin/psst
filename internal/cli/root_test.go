package cli

import (
	"os"
	"testing"
)

func TestIsTerminal_PipeIsNotTerminal(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if isTerminal(r) {
		t.Fatal("pipe should not be a terminal")
	}
}

func TestResolveVaultPath_ExplicitPath(t *testing.T) {
	cfg := globalConfig{VaultPath: "/custom/path"}
	got, err := resolveVaultPath(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/custom/path/vault.db"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveVaultPath_Fallback(t *testing.T) {
	cfg := globalConfig{Global: false, Env: ""}
	got, err := resolveVaultPath(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Error("expected non-empty path from fallback")
	}
}

func TestConfirmReveal_NonTTY(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()

	oldStdin := os.Stdin
	oldStderr := os.Stderr
	t.Cleanup(func() {
		os.Stdin = oldStdin   //nolint:reassign // restoring original streams after test
		os.Stderr = oldStderr //nolint:reassign // restoring original streams after test
	})
	os.Stdin = r          //nolint:reassign // mocking stdin for non-TTY test
	os.Stderr = os.Stdout //nolint:reassign // capturing stderr for non-TTY test

	err := confirmReveal("secret")
	w.Close()
	if err == nil {
		t.Fatal("expected error in non-TTY context")
	}
}

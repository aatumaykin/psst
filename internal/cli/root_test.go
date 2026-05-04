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

func TestConfirmReveal_NonTTY(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()

	oldStdin := os.Stdin
	oldStderr := os.Stderr
	t.Cleanup(func() {
		os.Stdin = oldStdin
		os.Stderr = oldStderr
	})
	os.Stdin = r
	os.Stderr = os.Stdout

	err := confirmReveal("secret")
	w.Close()
	if err == nil {
		t.Fatal("expected error in non-TTY context")
	}
}

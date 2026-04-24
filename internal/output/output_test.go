package output

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func captureOutput(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	//nolint:reassign // intentional stdout capture for testing
	os.Stdout = w
	fn()
	w.Close()
	//nolint:reassign // intentional stdout capture for testing
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestSuccessHuman(t *testing.T) {
	out := captureOutput(func() {
		NewFormatter(false, false).Success("done")
	})
	if !strings.Contains(out, "✓ done") {
		t.Fatalf("output = %q", out)
	}
}

func TestSuccessQuiet(t *testing.T) {
	out := captureOutput(func() {
		NewFormatter(false, true).Success("done")
	})
	if len(out) > 0 {
		t.Fatalf("quiet should produce no output, got %q", out)
	}
}

func TestSecretValueQuiet(t *testing.T) {
	out := captureOutput(func() {
		NewFormatter(false, true).SecretValue("KEY", "secret123")
	})
	if !strings.Contains(out, "secret123") {
		t.Fatalf("quiet mode should output value, got %q", out)
	}
}

func TestQuoteValue(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"simple", "simple"},
		{"has space", `"has space"`},
		{`has "quote"`, `"has \"quote\""`},
	}
	for _, tt := range tests {
		got := quoteValue(tt.in)
		if got != tt.want {
			t.Errorf("quoteValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

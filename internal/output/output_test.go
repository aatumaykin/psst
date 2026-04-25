package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestSuccessHuman(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.Success("done")
	if !strings.Contains(buf.String(), "✓ done") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestSuccessQuiet(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{quiet: true, stdout: &buf, stderr: &buf}
	f.Success("done")
	if len(buf.String()) > 0 {
		t.Fatalf("quiet should produce no output, got %q", buf.String())
	}
}

func TestSecretValueQuiet(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{quiet: true, stdout: &buf, stderr: &buf}
	f.SecretValue("KEY", "secret123")
	if !strings.Contains(buf.String(), "secret123") {
		t.Fatalf("quiet mode should output value, got %q", buf.String())
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

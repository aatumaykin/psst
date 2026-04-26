package output

import (
	"bytes"
	"strings"
	"testing"
	"time"
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
		{`path\to\file`, `path\to\file`},
		{`path\to\file with spaces`, `"path\\to\\file with spaces"`},
		{`mixed\path "quoted"`, `"mixed\\path \"quoted\""`},
	}

	for _, tt := range tests {
		got := quoteValue(tt.in)
		if got != tt.want {
			t.Errorf("quoteValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSecretListConversion(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}

	items := []SecretItem{
		{Name: "API_KEY", Tags: []string{"aws", "prod"}, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{Name: "DB_HOST", Tags: nil, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	f.SecretList(items)

	output := buf.String()
	if !strings.Contains(output, "API_KEY [aws, prod]") {
		t.Fatalf("expected tagged secret in output, got: %s", output)
	}
	if !strings.Contains(output, "DB_HOST") {
		t.Fatalf("expected untagged secret in output, got: %s", output)
	}
}

func TestSecretListConversionJSON(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{jsonMode: true, stdout: &buf, stderr: &buf}

	items := []SecretItem{
		{Name: "API_KEY", Tags: []string{"aws"}, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	f.SecretList(items)

	output := buf.String()
	if !strings.Contains(output, `"name"`) || !strings.Contains(output, `"API_KEY"`) {
		t.Fatalf("expected JSON output with name field, got: %s", output)
	}
}

func TestHistoryItemConversion(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}

	entries := []HistoryItem{
		{Version: 1, Tags: []string{"prod"}, ArchivedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)},
	}
	f.HistoryEntries("KEY", entries)

	output := buf.String()
	if !strings.Contains(output, "History for KEY") {
		t.Fatalf("expected history header, got: %s", output)
	}
	if !strings.Contains(output, "v1") {
		t.Fatalf("expected version in output, got: %s", output)
	}
	if !strings.Contains(output, "current (active)") {
		t.Fatalf("expected current marker, got: %s", output)
	}
}

func TestHistoryItemConversionJSON(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{jsonMode: true, stdout: &buf, stderr: &buf}

	entries := []HistoryItem{
		{Version: 1, Tags: []string{"prod"}, ArchivedAt: time.Now()},
	}
	f.HistoryEntries("KEY", entries)

	output := buf.String()
	if !strings.Contains(output, `"version"`) {
		t.Fatalf("expected JSON with version field, got: %s", output)
	}
}

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

func TestScanResultsEmpty(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.ScanResults(nil)
	if !strings.Contains(buf.String(), "No secrets found") {
		t.Fatalf("expected no-secrets message, got: %s", buf.String())
	}
}

func TestScanResultsHuman(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.ScanResults([]ScanMatch{
		{File: "config.yaml", Line: 5, SecretName: "API_KEY"},
	})
	if !strings.Contains(buf.String(), "config.yaml:5") {
		t.Fatalf("expected file:line in output, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "API_KEY") {
		t.Fatalf("expected secret name in output, got: %s", buf.String())
	}
}

func TestScanResultsJSON(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{jsonMode: true, stdout: &buf, stderr: &buf}
	f.ScanResults([]ScanMatch{
		{File: "config.yaml", Line: 5, SecretName: "API_KEY"},
	})
	if !strings.Contains(buf.String(), `"file"`) {
		t.Fatalf("expected JSON output, got: %s", buf.String())
	}
}

func TestEnvListHuman(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.EnvList(map[string]string{"KEY": "value", "PATH_KEY": "path with spaces"})
	output := buf.String()
	if !strings.Contains(output, "KEY=value") {
		t.Fatalf("expected KEY=value in output, got: %s", output)
	}
	if !strings.Contains(output, `"path with spaces"`) {
		t.Fatalf("expected quoted value, got: %s", output)
	}
}

func TestEnvListJSON(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{jsonMode: true, stdout: &buf, stderr: &buf}
	f.EnvList(map[string]string{"KEY": "value"})
	if !strings.Contains(buf.String(), `"KEY"`) {
		t.Fatalf("expected JSON output, got: %s", buf.String())
	}
}

func TestEnvListWriter(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{}
	f.EnvListWriter(map[string]string{"A": "1", "B": "2"}, &buf)
	if !strings.Contains(buf.String(), "A=1") || !strings.Contains(buf.String(), "B=2") {
		t.Fatalf("expected both entries, got: %s", buf.String())
	}
}

func TestEnvironmentListHuman(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.EnvironmentList([]string{"prod", "staging"})
	if !strings.Contains(buf.String(), "prod") || !strings.Contains(buf.String(), "staging") {
		t.Fatalf("expected env names in output, got: %s", buf.String())
	}
}

func TestEnvironmentListEmpty(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.EnvironmentList(nil)
	if !strings.Contains(buf.String(), "No environments") {
		t.Fatalf("expected empty message, got: %s", buf.String())
	}
}

func TestVersionInfoHuman(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.VersionInfo(VersionData{
		Version: "1.0.0", Commit: "abc123", Date: "2025-01-01",
		GoVersion: "go1.26", OSArch: "linux/amd64",
	})
	if !strings.Contains(buf.String(), "psst 1.0.0") {
		t.Fatalf("expected version in output, got: %s", buf.String())
	}
}

func TestVersionInfoQuiet(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{quiet: true, stdout: &buf, stderr: &buf}
	f.VersionInfo(VersionData{Version: "1.0.0"})
	if !strings.Contains(buf.String(), "1.0.0") {
		t.Fatalf("quiet mode should output version, got: %s", buf.String())
	}
	if strings.Contains(buf.String(), "commit") {
		t.Fatalf("quiet mode should not output details, got: %s", buf.String())
	}
}

func TestVersionInfoJSON(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{jsonMode: true, stdout: &buf, stderr: &buf}
	f.VersionInfo(VersionData{Version: "1.0.0", Commit: "abc123"})
	if !strings.Contains(buf.String(), `"version"`) {
		t.Fatalf("expected JSON output, got: %s", buf.String())
	}
}

func TestPrint(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{stdout: &buf, stderr: &buf}
	f.Print("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Fatalf("expected message, got: %s", buf.String())
	}
}

func TestPrintQuiet(t *testing.T) {
	var buf bytes.Buffer
	f := &Formatter{quiet: true, stdout: &buf, stderr: &buf}
	f.Print("hello")
	if len(buf.String()) > 0 {
		t.Fatalf("quiet should produce no output, got: %s", buf.String())
	}
}

package runner

import (
	"strings"
	"testing"
)

func TestMaskSecrets(t *testing.T) {
	secrets := []string{"sk-live-abc123", "password123"}
	text := "Using key sk-live-abc123 for auth"

	result := MaskSecrets(text, secrets)
	if strings.Contains(result, "sk-live-abc123") {
		t.Fatal("secret should be masked")
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Fatal("should contain [REDACTED]")
	}
}

func TestMaskSecretsEmpty(t *testing.T) {
	text := "hello world"
	result := MaskSecrets(text, []string{""})
	if result != text {
		t.Fatal("empty secrets should not change text")
	}
}

func TestExpandEnvVars(t *testing.T) {
	env := map[string]string{
		"API_KEY": "secret123",
		"HOST":    "example.com",
	}

	tests := []struct {
		input, want string
	}{
		{"$API_KEY", "secret123"},
		{"${API_KEY}", "secret123"},
		{"prefix-$API_KEY-suffix", "prefix-secret123-suffix"},
		{"${HOST}/path", "example.com/path"},
		{"$MISSING", "$MISSING"},
	}

	for _, tt := range tests {
		got := ExpandEnvVars(tt.input, env)
		if got != tt.want {
			t.Errorf("ExpandEnvVars(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFilterEmpty(t *testing.T) {
	secrets := map[string]string{
		"A": "value",
		"B": "",
		"C": "another",
	}
	result := filterEmpty(secrets)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
}

func TestBuildEnv(t *testing.T) {
	secrets := map[string]string{
		"API_KEY": "test",
	}
	env := buildEnv(secrets)

	hasKey := false
	hasPssPassword := false
	for _, e := range env {
		if strings.HasPrefix(e, "API_KEY=test") {
			hasKey = true
		}
		if strings.HasPrefix(e, "PSST_PASSWORD=") {
			hasPssPassword = true
		}
	}

	if !hasKey {
		t.Fatal("should contain API_KEY")
	}
	if hasPssPassword {
		t.Fatal("should not contain PSST_PASSWORD")
	}
}

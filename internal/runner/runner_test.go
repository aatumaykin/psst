package runner

import (
	"bytes"
	"io"
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

func TestMaskSecrets_SubstringOrder(t *testing.T) {
	secrets := []string{"sk-abc", "sk-abc123def"}
	text := "key=sk-abc123def and short=sk-abc"

	result := MaskSecrets(text, secrets)
	if strings.Contains(result, "sk-abc123def") {
		t.Fatal("longer secret should be masked")
	}
	if strings.Contains(result, "sk-abc") {
		t.Fatal("shorter secret should be masked")
	}
	count := strings.Count(result, "[REDACTED]")
	if count != 2 {
		t.Fatalf("expected 2 [REDACTED] occurrences, got %d", count)
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
	env := map[string][]byte{
		"API_KEY": []byte("secret123"),
		"HOST":    []byte("example.com"),
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

func TestExpandEnvVars_WordBoundary(t *testing.T) {
	env := map[string][]byte{
		"API": []byte("api-value"),
	}
	got := ExpandEnvVars("$API_KEY", env)
	if got == "api-value_Key" || got == "api-value_KEY" {
		t.Fatalf("$API should not partially expand inside $API_KEY, got: %q", got)
	}
	if got != "$API_KEY" {
		t.Fatalf("expected $API_KEY to remain unexpanded, got: %q", got)
	}
}

func TestFilterEmpty(t *testing.T) {
	secrets := map[string][]byte{
		"A": []byte("value"),
		"B": {},
		"C": []byte("another"),
	}
	result := filterEmpty(secrets)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
}

func TestBuildEnv(t *testing.T) {
	secrets := map[string][]byte{
		"API_KEY": []byte("test"),
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

func TestStreamWithMasking_BoundarySplit(t *testing.T) {
	secret := "SECRETVALUE"
	chunk1 := "prefix" + secret[:6]
	chunk2 := secret[6:] + "suffix\n"

	var buf bytes.Buffer
	r, w := io.Pipe()

	go func() {
		w.Write([]byte(chunk1))
		w.Write([]byte(chunk2))
		w.Close()
	}()

	streamWithMasking(r, &buf, []string{secret})

	result := buf.String()
	if strings.Contains(result, secret) {
		t.Fatalf("secret leaked in output: %q", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in output, got: %q", result)
	}
}

func TestExitCode(t *testing.T) {
	if code := exitCode(nil); code != 0 {
		t.Fatalf("exitCode(nil) = %d, want 0", code)
	}
}

func TestMaskSecrets_MultipleSecrets(t *testing.T) {
	secrets := []string{"alpha", "beta"}
	text := "alpha and beta"
	result := MaskSecrets(text, secrets)
	if strings.Contains(result, "alpha") || strings.Contains(result, "beta") {
		t.Fatalf("secrets leaked: %q", result)
	}
	if strings.Count(result, "[REDACTED]") != 2 {
		t.Fatalf("expected 2 [REDACTED], got: %q", result)
	}
}

func TestExpandEnvVars_EmptyEnv(t *testing.T) {
	got := ExpandEnvVars("$FOO", map[string][]byte{})
	if got != "$FOO" {
		t.Fatalf("expected $FOO unchanged, got %q", got)
	}
}

func TestExpandEnvVars_LongerNameFirst(t *testing.T) {
	env := map[string][]byte{
		"A":   []byte("short"),
		"ABC": []byte("long"),
	}
	got := ExpandEnvVars("$ABC", env)
	if got != "long" {
		t.Fatalf("expected 'long', got %q", got)
	}
}

func TestExec_NoMasking(t *testing.T) {
	r := New()
	secrets := map[string][]byte{"MY_KEY": []byte("myvalue")}
	code, execErr := r.Exec(secrets, "echo", []string{"hello"}, ExecOptions{MaskOutput: false})
	if execErr != nil {
		t.Fatalf("Exec() error: %v", execErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestExec_WithMasking(t *testing.T) {
	r := New()
	secrets := map[string][]byte{"MY_SECRET": []byte("secret123")}
	code, execErr := r.Exec(secrets, "echo", []string{"secret123"}, ExecOptions{MaskOutput: true})
	if execErr != nil {
		t.Fatalf("Exec() error: %v", execErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestExec_ManyLinesWithMasking(t *testing.T) {
	r := New()
	secrets := map[string][]byte{"KEY": []byte("val")}
	code, execErr := r.Exec(secrets, "seq", []string{"100"}, ExecOptions{MaskOutput: true})
	if execErr != nil {
		t.Fatalf("Exec() error: %v", execErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestExec_EnvInjected(t *testing.T) {
	r := New()
	secrets := map[string][]byte{"TEST_INJECT": []byte("injected_value")}
	code, execErr := r.Exec(secrets, "printenv", []string{"TEST_INJECT"}, ExecOptions{MaskOutput: false})
	if execErr != nil {
		t.Fatalf("Exec() error: %v", execErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestExec_ExitCode(t *testing.T) {
	r := New()
	code, _ := r.Exec(map[string][]byte{}, "false", []string{}, ExecOptions{MaskOutput: false})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestExec_NonexistentCommand(t *testing.T) {
	r := New()
	_, execErr := r.Exec(map[string][]byte{}, "nonexistent_cmd_xyz", []string{}, ExecOptions{MaskOutput: false})
	if execErr == nil {
		t.Fatal("expected error for nonexistent command")
	}
}

func TestExpandEnvVars_BothForms(t *testing.T) {
	env := map[string][]byte{"KEY": []byte("val")}
	got := ExpandEnvVars("prefix-${KEY}-$KEY-suffix", env)
	if got != "prefix-val-val-suffix" {
		t.Fatalf("got %q", got)
	}
}

func TestExpandEnvVars_NoTransitiveExpansion(t *testing.T) {
	env := map[string][]byte{
		"A": []byte("${B}"),
		"B": []byte("secret"),
	}
	got := ExpandEnvVars("$A", env)
	if got == "secret" {
		t.Fatal("transitive expansion should not occur")
	}
	if got != "${B}" {
		t.Fatalf("expected literal ${B}, got %q", got)
	}
}

func TestExec_ContextCancellation(t *testing.T) {
	r := New()
	secrets := map[string][]byte{}
	code, execErr := r.Exec(secrets, "true", []string{}, ExecOptions{MaskOutput: false})
	if execErr != nil {
		t.Fatalf("Exec() error: %v", execErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

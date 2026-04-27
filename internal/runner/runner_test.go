package runner

import (
	"bytes"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
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
	for _, v := range result {
		if len(v) == 0 {
			t.Fatal("empty value in result")
		}
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

	streamWithMasking(r, &buf, [][]byte{[]byte(secret)})

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

type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

func TestStreamWithMasking_NewlineInSecret(t *testing.T) {
	secret := "SECRET\nVALUE"
	input := "prefix" + secret + "suffix\n"

	var buf bytes.Buffer
	streamWithMasking(strings.NewReader(input), &buf, [][]byte{[]byte(secret)})

	result := buf.String()
	if strings.Contains(result, "SECRET") {
		t.Fatalf("secret fragment leaked: %q", result)
	}
	if strings.Contains(result, "VALUE") {
		t.Fatalf("secret fragment leaked: %q", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in output, got: %q", result)
	}
}

func TestStreamWithMasking_ChunkBoundarySplit(t *testing.T) {
	secret := "BOUNDARYSECRET"
	chunk1 := "aa" + secret[:7]
	chunk2 := secret[7:] + "bb"

	var buf bytes.Buffer
	r, w := io.Pipe()

	go func() {
		w.Write([]byte(chunk1))
		w.Write([]byte(chunk2))
		w.Close()
	}()

	streamWithMasking(r, &buf, [][]byte{[]byte(secret)})

	result := buf.String()
	if strings.Contains(result, secret) {
		t.Fatalf("secret leaked: %q", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Fatalf("expected [REDACTED], got: %q", result)
	}
}

func TestStreamWithMasking_OneByteReads(t *testing.T) {
	secret := "LONGSECRET123"
	input := "prefix" + secret + "suffix"

	var buf bytes.Buffer
	reader := &oneByteReader{data: []byte(input)}

	streamWithMasking(reader, &buf, [][]byte{[]byte(secret)})

	result := buf.String()
	if strings.Contains(result, secret) {
		t.Fatalf("secret leaked: %q", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Fatalf("expected [REDACTED], got: %q", result)
	}
}

func TestExec_NoGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	initial := runtime.NumGoroutine()

	runner := New()
	for range 10 {
		_, err := runner.Exec(map[string][]byte{}, "true", []string{}, ExecOptions{})
		if err != nil {
			t.Fatalf("Exec() error: %v", err)
		}
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	final := runtime.NumGoroutine()

	if final > initial+5 {
		t.Fatalf("possible goroutine leak: initial=%d, final=%d", initial, final)
	}
}

func TestMaskSecretsBytes(t *testing.T) {
	secrets := [][]byte{[]byte("sk-live-abc123"), []byte("password123")}
	data := []byte("Using key sk-live-abc123 for auth")

	result := MaskSecretsBytes(data, secrets)
	if bytes.Contains(result, []byte("sk-live-abc123")) {
		t.Fatal("secret should be masked")
	}
	if !bytes.Contains(result, []byte("[REDACTED]")) {
		t.Fatal("should contain [REDACTED]")
	}
}

func TestMaskSecretsBytes_SubstringOrder(t *testing.T) {
	secrets := [][]byte{[]byte("sk-abc"), []byte("sk-abc123def")}
	data := []byte("key=sk-abc123def and short=sk-abc")

	result := MaskSecretsBytes(data, secrets)
	if bytes.Contains(result, []byte("sk-abc123def")) {
		t.Fatal("longer secret should be masked")
	}
	if bytes.Contains(result, []byte("sk-abc")) {
		t.Fatal("shorter secret should be masked")
	}
}

func TestMaskSecretsBytes_Empty(t *testing.T) {
	data := []byte("hello world")
	result := MaskSecretsBytes(data, [][]byte{[]byte("")})
	if string(result) != string(data) {
		t.Fatal("empty secrets should not change data")
	}
}

func TestMaskSecretsBytes_SubstringOfRedacted(t *testing.T) {
	secrets := [][]byte{[]byte("secret-value"), []byte("ACT")}
	data := []byte("key=secret-value")
	result := MaskSecretsBytes(data, secrets)
	if string(result) != "key=[REDACTED]" {
		t.Fatalf("expected clean masking, got: %q", result)
	}
}

func TestMaskSecretsBytes_RedactedItself(t *testing.T) {
	secrets := [][]byte{[]byte("REDACTED")}
	data := []byte("data=REDACTED")
	result := MaskSecretsBytes(data, secrets)
	if string(result) != "data=[REDACTED]" {
		t.Fatalf("expected clean masking, got: %q", result)
	}
}

func TestMaskSecrets_MultipleOverlapping(t *testing.T) {
	secrets := []string{"sk-long-api-key-123", "sk-long-api-key"}
	text := "key=sk-long-api-key-123"
	result := MaskSecrets(text, secrets)
	if result != "key=[REDACTED]" {
		t.Fatalf("expected clean masking, got: %q", result)
	}
}

func TestMaskSecretsBytes_NullBytes(t *testing.T) {
	secrets := [][]byte{[]byte("hello\x00world")}
	data := []byte("data=hello\x00world")
	result := MaskSecretsBytes(data, secrets)
	if bytes.Contains(result, []byte("hello\x00world")) {
		t.Fatal("secret with null bytes should be masked")
	}
	if !bytes.Contains(result, []byte("[REDACTED]")) {
		t.Fatal("should contain [REDACTED]")
	}
}

func TestMaskSecretsBytes_SingleByte(t *testing.T) {
	secrets := [][]byte{[]byte("X")}
	data := []byte("XOXO")
	result := MaskSecretsBytes(data, secrets)
	if bytes.Contains(result, []byte("X")) {
		t.Fatal("single-byte secret should be masked")
	}
	count := bytes.Count(result, []byte("[REDACTED]"))
	if count != 2 {
		t.Fatalf("expected 2 [REDACTED] for XOXO, got %d", count)
	}
}

func TestMaskSecretsBytes_NilSecrets(t *testing.T) {
	data := []byte("hello world")
	result := MaskSecretsBytes(data, nil)
	if string(result) != string(data) {
		t.Fatal("nil secrets should not change data")
	}
}

func TestMaskSecretsBytes_EmptySlice(t *testing.T) {
	data := []byte("hello world")
	result := MaskSecretsBytes(data, [][]byte{})
	if string(result) != string(data) {
		t.Fatal("empty secrets slice should not change data")
	}
}

func TestMaskSecretsBytes_OverlappingSecrets(t *testing.T) {
	secrets := [][]byte{[]byte("ABC"), []byte("AB")}
	data := []byte("ABC")
	result := MaskSecretsBytes(data, secrets)
	if string(result) != "[REDACTED]" {
		t.Fatalf("expected single [REDACTED] for overlapping, got: %q", result)
	}
}

func TestMaskSecretsBytes_SecretEqualsRedacted(t *testing.T) {
	secrets := [][]byte{[]byte("[REDACTED]")}
	data := []byte("data=[REDACTED]")
	result := MaskSecretsBytes(data, secrets)
	if bytes.Count(result, []byte("[REDACTED]")) != 1 {
		t.Fatalf("expected exactly 1 [REDACTED], got: %q", result)
	}
}

func TestExpandEnvVars_BraceConcatenation(t *testing.T) {
	env := map[string][]byte{"KEY": []byte("val")}
	got := ExpandEnvVars("${KEY}text", env)
	if got != "valtext" {
		t.Fatalf("expected %q, got %q", "valtext", got)
	}
}

func TestExpandEnvVars_WordBoundaryDigits(t *testing.T) {
	env := map[string][]byte{"KEY": []byte("val")}
	got := ExpandEnvVars("$KEY123", env)
	if got != "$KEY123" {
		t.Fatalf("expected $KEY123 unchanged, got %q", got)
	}
}

func TestExpandEnvVars_DollarAtEnd(t *testing.T) {
	env := map[string][]byte{"KEY": []byte("val")}
	got := ExpandEnvVars("text$", env)
	if got != "text$" {
		t.Fatalf("expected %q, got %q", "text$", got)
	}
}

func TestExpandEnvVars_MultipleDollarSigns(t *testing.T) {
	env := map[string][]byte{"A": []byte("1"), "B": []byte("2")}
	got := ExpandEnvVars("$$A$$B", env)
	if got != "$1$2" {
		t.Fatalf("expected %q, got %q", "$1$2", got)
	}
}

func TestBuildEnv_InvalidNames(t *testing.T) {
	secrets := map[string][]byte{
		"VALID_KEY": []byte("good"),
		"bad=key":   []byte("injected"),
		"lowercase": []byte("bad"),
		"NEW\nLINE": []byte("injected"),
		"123START":  []byte("bad"),
	}
	env := buildEnv(secrets)

	for _, e := range env {
		if strings.HasPrefix(e, "bad=") {
			t.Fatal("name with '=' should be skipped")
		}
		if strings.HasPrefix(e, "lowercase=") {
			t.Fatal("lowercase name should be skipped")
		}
		if strings.Contains(e, "NEW") {
			t.Fatal("name with newline should be skipped")
		}
		if strings.HasPrefix(e, "123") {
			t.Fatal("name starting with digit should be skipped")
		}
	}

	hasValid := false
	for _, e := range env {
		if strings.HasPrefix(e, "VALID_KEY=good") {
			hasValid = true
		}
	}
	if !hasValid {
		t.Fatal("VALID_KEY should be present")
	}
}

package render

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderSyntaxes(t *testing.T) {
	values := map[string][]byte{"API_KEY": []byte("secret123"), "DB_PASS": []byte("test-password")}
	tests := []struct {
		in   string
		want string
		subs int
	}{
		{"{{API_KEY}}", "secret123", 1},
		{"$API_KEY", "secret123", 1},
		{"${API_KEY}", "secret123", 1},
		{"pw={{DB_PASS}} host=$API_KEY x=${DB_PASS}", "pw=test-password host=secret123 x=test-password", 3},
		{"plain text", "plain text", 0},
		{"{{API_KEY}}{{API_KEY}}", "secret123secret123", 2},
	}
	for _, tt := range tests {
		out, _, subs := Render([]byte(tt.in), values)
		if string(out) != tt.want || subs != tt.subs {
			t.Errorf("Render(%q) = %q, %d; want %q, %d", tt.in, out, subs, tt.want, tt.subs)
		}
	}
}

func TestRenderSinglePass(t *testing.T) {
	values := map[string][]byte{
		"A": []byte("$B ${B} {{B}}"),
		"B": []byte("must-not-appear"),
	}
	out, _, subs := Render([]byte("{{A}}"), values)
	if string(out) != "$B ${B} {{B}}" {
		t.Fatalf("single-pass violated: %q", out)
	}
	if subs != 1 {
		t.Fatalf("subs = %d, want 1", subs)
	}
}

func TestRenderUnresolvedBraceAlwaysReported(t *testing.T) {
	values := map[string][]byte{"API_KEY": []byte("secret123")}
	out, unresolved, _ := Render([]byte("{{API_KEY}} {{MISSING}} {{api_key}} {{}} {{ .Values.x }}"), values)
	if string(out) != "secret123 {{MISSING}} {{api_key}} {{}} {{ .Values.x }}" {
		t.Fatalf("unresolved braces stay literal: %q", out)
	}
	if len(unresolved) != 4 {
		t.Fatalf("unresolved = %v, want 4 entries", unresolved)
	}
	if unresolved[0].Name != "MISSING" || unresolved[0].Syntax != SyntaxBrace {
		t.Fatalf("first unresolved = %+v", unresolved[0])
	}
}

func TestRenderUnresolvedDedupOrder(t *testing.T) {
	_, unresolved, _ := Render([]byte("{{B}} {{A}} {{B}} $A ${A}"), map[string][]byte{})
	if len(unresolved) != 3 {
		t.Fatalf("unresolved = %v, want B,A brace + A shell deduped", unresolved)
	}
	want := []struct {
		name string
		syn  Syntax
	}{
		{"B", SyntaxBrace}, {"A", SyntaxBrace}, {"A", SyntaxShell},
	}
	for i, w := range want {
		if unresolved[i].Name != w.name || unresolved[i].Syntax != w.syn {
			t.Fatalf("unresolved[%d] = %+v, want %s/%d", i, unresolved[i], w.name, w.syn)
		}
	}
}

func TestRenderShellBoundaries(t *testing.T) {
	values := map[string][]byte{"API": []byte("short")}
	tests := []struct {
		in        string
		want      string
		wantUnres []Unresolved
	}{
		{"$API_KEY", "$API_KEY", []Unresolved{{Name: "API_KEY", Syntax: SyntaxShell}}},
		{"$API", "short", nil},
		{"$$KEY", "$$KEY", nil},
		{"$$", "$$", nil},
		{"$1", "$1", nil},
		{"$lower", "$lower", nil},
		{"$_x", "$_x", nil},
		{"cost$", "cost$", nil},
		{"${VAR:-x}", "${VAR:-x}", []Unresolved{{Name: "VAR:-x", Syntax: SyntaxShell}}},
		{"${MISSING}", "${MISSING}", []Unresolved{{Name: "MISSING", Syntax: SyntaxShell}}},
		{"${", "${", nil},
		{"{{", "{{", nil},
		{"a}}b{{OTHER}}", "a}}b{{OTHER}}", []Unresolved{{Name: "OTHER", Syntax: SyntaxBrace}}},
	}
	for _, tt := range tests {
		out, unresolved, _ := Render([]byte(tt.in), values)
		if string(out) != tt.want {
			t.Errorf("Render(%q) = %q, want %q", tt.in, out, tt.want)
		}
		if len(unresolved) != len(tt.wantUnres) {
			t.Errorf("Render(%q) unresolved = %v, want %v", tt.in, unresolved, tt.wantUnres)
			continue
		}
		for i := range tt.wantUnres {
			if unresolved[i] != tt.wantUnres[i] {
				t.Errorf("Render(%q) unresolved[%d] = %+v, want %+v", tt.in, i, unresolved[i], tt.wantUnres[i])
			}
		}
	}
}

func TestRenderShellUnresolvedReported(t *testing.T) {
	_, unresolved, _ := Render([]byte("$HOME ${MISSING}"), map[string][]byte{})
	if len(unresolved) != 2 {
		t.Fatalf("unresolved = %v", unresolved)
	}
	if unresolved[0].Name != "HOME" || unresolved[0].Syntax != SyntaxShell {
		t.Fatalf("first = %+v", unresolved[0])
	}
	if unresolved[1].Name != "MISSING" || unresolved[1].Syntax != SyntaxShell {
		t.Fatalf("second = %+v", unresolved[1])
	}
}

func TestRenderMaximalRun(t *testing.T) {
	values := map[string][]byte{"API": []byte("a"), "API_KEY": []byte("b")}
	out, subs := mustRender(t, "$API_KEY then $API", values)
	if out != "b then a" || subs != 2 {
		t.Fatalf("out = %q subs = %d", out, subs)
	}
}

func mustRender(t *testing.T, in string, values map[string][]byte) (string, int) {
	t.Helper()
	out, _, subs := Render([]byte(in), values)
	return string(out), subs
}

func TestRenderBytePreservation(t *testing.T) {
	val := []byte{0xff, 0xfe, 'x'}
	out, _, subs := Render([]byte("a{{K}}b"), map[string][]byte{"K": val})
	if !bytes.Equal(out, []byte{'a', 0xff, 0xfe, 'x', 'b'}) || subs != 1 {
		t.Fatalf("bytes = %x", out)
	}
	if strings.ContainsRune(string(out), 0) == false && len(out) != 5 {
		t.Fatal("length drift")
	}
}

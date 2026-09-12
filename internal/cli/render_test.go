package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/render"
)

func TestFormatUnresolved(t *testing.T) {
	got := formatUnresolved([]render.Unresolved{
		{Name: "MISSING", Syntax: render.SyntaxBrace},
		{Name: "HOME", Syntax: render.SyntaxShell},
	})
	want := "MISSING ({{...}}), HOME ($...)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	long := strings.Repeat("x", 50)
	got = formatUnresolved([]render.Unresolved{{Name: long, Syntax: render.SyntaxBrace}})
	if !strings.HasPrefix(got, strings.Repeat("x", 32)+"… (50 bytes total)") {
		t.Fatalf("cap missing: %q", got)
	}
}

func TestWriteRenderedOutputPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.env")
	if err := os.WriteFile(path, []byte("old wider content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeRenderedOutput(path, []byte("secret123")); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", st.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if string(data) != "secret123" {
		t.Fatalf("content = %q", data)
	}
}

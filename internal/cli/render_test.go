package cli

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestWriteRenderedOutputRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink refusal is disabled on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.env")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	err := writeRenderedOutput(link, []byte("secret123"))
	if err == nil {
		t.Fatal("write through symlink must be refused")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("message = %v", err)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "old" {
		t.Fatalf("symlink target modified: %q", data)
	}
}

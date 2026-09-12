package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func (e *testEnv) setSecret(t *testing.T, name, value string, extraArgs ...string) {
	t.Helper()
	args := append([]string{"set", name, "--stdin"}, extraArgs...)
	cmd := exec.Command(e.binary, args...)
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD=test-password", "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte(value + "\n"))
		stdin.Close()
	}()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("set %s failed: %s", name, out)
	}
}

func TestRenderHappyPath(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.setSecret(t, "DB_PASS", "test-password")

	e.writeFile("deploy.tpl", "API={{API_KEY}}\nPW=$DB_PASS\nBRACED=${API_KEY}\nHOME=$HOME\n")
	stdout, _, code := e.run("render", "--in", "deploy.tpl", "--out", "deploy.env")
	if code != 0 {
		t.Fatalf("render failed: %s", stdout)
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "deploy.env"))
	if err != nil {
		t.Fatal(err)
	}
	want := "API=secret123\nPW=test-password\nBRACED=secret123\nHOME=$HOME\n"
	if string(data) != want {
		t.Fatalf("content = %q, want %q", data, want)
	}
	if !strings.Contains(stdout, "Rendered 3 placeholders") {
		t.Fatalf("summary missing N: %s", stdout)
	}
	if strings.Contains(stdout, "secret123") || strings.Contains(stdout, "test-password") {
		t.Fatal("value leaked to stdout")
	}
	st, _ := os.Stat(filepath.Join(e.dir, "deploy.env"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", st.Mode().Perm())
	}
}

func TestRenderPermsRepair(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}}")
	if err := os.WriteFile(filepath.Join(e.dir, "wide.env"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := e.run("render", "--in", "tpl", "--out", "wide.env"); code != 0 {
		t.Fatal("render failed")
	}
	st, _ := os.Stat(filepath.Join(e.dir, "wide.env"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600 (chmod repair)", st.Mode().Perm())
	}
}

func TestRenderUnresolvedBrace(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}} and {{MISSING}}")
	_, stderr, code := e.run("render", "--in", "tpl", "--out", "nope.env")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "MISSING") {
		t.Fatalf("missing name in error: %s", stderr)
	}
	if strings.Contains(stderr, "secret123") {
		t.Fatal("value leaked in error output")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "nope.env")); !os.IsNotExist(err) {
		t.Fatal("output file must not be created on unresolved")
	}
}

func TestRenderStrict(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}} $HOME")
	if _, _, code := e.run("render", "--in", "tpl", "--out", "o.env", "--strict"); code != 1 {
		t.Fatalf("strict code = %d, want 1", code)
	}
	e.writeFile("tpl2", "{{API_KEY}}")
	if _, _, code := e.run("render", "--in", "tpl2", "--out", "o2.env", "--strict"); code != 0 {
		t.Fatalf("strict happy code = %d", code)
	}
}

func TestRenderTagFilter(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123", "--tag", "prod")
	e.setSecret(t, "DB_PASS", "test-password", "--tag", "dev")

	e.writeFile("tpl1", "{{API_KEY}} {{DB_PASS}}")
	e.writeFile("tpl2", "{{API_KEY}}")

	_, stderr, code := e.run("render", "--in", "tpl1", "--out", "tag1.env", "--tag", "prod")
	if code != 1 {
		t.Fatalf("code = %d, want 1 (DB_PASS outside tag set)", code)
	}
	if !strings.Contains(stderr, "DB_PASS") {
		t.Fatalf("error must name DB_PASS: %s", stderr)
	}
	if _, _, code := e.run("render", "--in", "tpl2", "--out", "tag2.env", "--tag", "prod"); code != 0 {
		t.Fatalf("tag render code = %d", code)
	}
	data, _ := os.ReadFile(filepath.Join(e.dir, "tag2.env"))
	if string(data) != "secret123" {
		t.Fatalf("content = %q", data)
	}
}

func TestRenderRefusals(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}}")
	if _, _, code := e.run("render", "--in", "tpl", "--out", "tpl"); code != 1 {
		t.Fatalf("out==in code = %d", code)
	}
	if _, stderr, code := e.run("render", "--in", "tpl", "--out", "-"); code != 1 {
		t.Fatalf("out - code = %d", code)
	} else if !strings.Contains(stderr, "stdout") {
		t.Fatalf("out - message: %s", stderr)
	}
}

func TestRenderGitVault(t *testing.T) {
	e := newTestEnv(t)
	if _, _, code := e.run("init", "--storage", "git"); code != 0 {
		t.Fatal("git init failed")
	}
	e.setSecret(t, "API_KEY", "secret123")
	e.writeFile("tpl", "{{API_KEY}} $API_KEY")
	if _, _, code := e.run("render", "--in", "tpl", "--out", "g.env", "--storage", "git"); code != 0 {
		t.Fatalf("git render failed")
	}
	data, _ := os.ReadFile(filepath.Join(e.dir, "g.env"))
	if string(data) != "secret123 secret123" {
		t.Fatalf("content = %q", data)
	}
}

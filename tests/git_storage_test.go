package integration

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func (e *testEnv) gitRun(args ...string) (string, int) {
	e.t.Helper()
	home := filepath.Join(e.dir, "home")
	os.MkdirAll(home, 0755)
	work := filepath.Join(e.dir, "work")
	os.MkdirAll(work, 0755)
	cmd := exec.Command(e.binary, args...)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "HOME="+home, "PSST_PASSWORD=test-password", "PSST_GLOBAL=1", "PSST_NO_KEYCHAIN=1")
	cmd.Stdin = strings.NewReader("secret-value\n")
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		code = -1
	}
	return string(out), code
}

func (e *testEnv) newBareRemote(t *testing.T) string {
	t.Helper()
	p := filepath.Join(e.dir, "remote.git")
	if out, err := exec.Command("git", "init", "--bare", "-b", "main", p).CombinedOutput(); err != nil {
		t.Fatalf("bare: %v\n%s", err, out)
	}
	return p
}

func TestGitStorageLifecycle(t *testing.T) {
	e := newTestEnv(t)
	remote := e.newBareRemote(t)

	if out, code := e.gitRun("init", "--storage", "git", "--remote", remote); code != 0 {
		t.Fatalf("init: %s", out)
	}
	if out, code := e.gitRun("set", "API_KEY", "--stdin"); code != 0 {
		t.Fatalf("set: %s", out)
	}
	out, code := e.gitRun("list")
	if code != 0 || !strings.Contains(out, "API_KEY") {
		t.Fatalf("list: %s (%d)", out, code)
	}
	if out, code = e.gitRun("tag", "API_KEY", "prod"); code != 0 {
		t.Fatalf("tag: %s", out)
	}
	out, _ = e.gitRun("list")
	if !strings.Contains(out, "prod") {
		t.Fatalf("tag visible in list: %s", out)
	}
	out, code = e.gitRun("history", "API_KEY")
	if code != 0 {
		t.Fatalf("history: %s", out)
	}
	if out, code = e.gitRun("untag", "API_KEY"); code != 0 {
		t.Fatalf("untag: %s", out)
	}
	if out, code = e.gitRun("export", "--env-file", "verify.env"); code != 0 {
		t.Fatalf("export: %s (%d)", out, code)
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "work", "verify.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "API_KEY=secret-value") {
		t.Fatalf("export content: %s", string(data))
	}
}

func TestGitStorageSecondMachine(t *testing.T) {
	e := newTestEnv(t)
	remote := e.newBareRemote(t)
	e.gitRun("init", "--storage", "git", "--remote", remote)
	e.gitRun("set", "SHARED_KEY", "--stdin")

	home2 := filepath.Join(e.dir, "home2")
	os.MkdirAll(home2, 0755)
	cmd := exec.Command(e.binary, "init", "--storage", "git", "--remote", remote)
	cmd.Env = append(os.Environ(), "HOME="+home2, "PSST_PASSWORD=test-password", "PSST_GLOBAL=1", "PSST_NO_KEYCHAIN=1")
	cmd.Dir = e.dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("second machine init (clone): %s", out)
	}
	cmd2 := exec.Command(e.binary, "list")
	cmd2.Env = cmd.Env
	out2, _ := cmd2.CombinedOutput()
	if !strings.Contains(string(out2), "SHARED_KEY") {
		t.Fatalf("second machine must see shared secret: %s", out2)
	}
	cmd3 := exec.Command(e.binary, "set", "OTHER_KEY", "--stdin")
	cmd3.Env = cmd.Env
	cmd3.Stdin = strings.NewReader("other-value\n")
	cmd3.Dir = e.dir
	if out, err := cmd3.CombinedOutput(); err != nil {
		t.Fatalf("second machine set: %s", out)
	}
}

func TestSyncDiscardLocal(t *testing.T) {
	e := newTestEnv(t)
	remote := e.newBareRemote(t)
	e.gitRun("init", "--storage", "git", "--remote", remote)
	e.gitRun("set", "KEY", "--stdin")

	home2 := filepath.Join(e.dir, "home2")
	os.MkdirAll(home2, 0755)
	run2 := func(args ...string) string {
		c := exec.Command(e.binary, args...)
		c.Env = append(os.Environ(),
			"HOME="+home2, "PSST_PASSWORD=test-password", "PSST_GLOBAL=1", "PSST_NO_KEYCHAIN=1")
		c.Stdin = strings.NewReader("v\n")
		c.Dir = e.dir
		out, _ := c.CombinedOutput()
		return string(out)
	}
	run2("init", "--storage", "git", "--remote", remote)
	run2("set", "KEY", "--stdin")

	out, _ := e.gitRun("set", "KEY", "--stdin")
	if !strings.Contains(out, "discard-local") {
		t.Fatalf("conflict must hint discard-local: %s", out)
	}
	if out2 := run2("sync", "--discard-local", "--confirm"); strings.Contains(out2, "✗") {
		t.Fatalf("discard on machine2: %s", out2)
	}
	if out3, _ := e.gitRun("sync", "--discard-local", "--confirm"); strings.Contains(out3, "✗") {
		t.Fatalf("discard on machine1: %s", out3)
	}
	if out4, _ := e.gitRun("set", "KEY", "--stdin"); strings.Contains(out4, "✗") {
		t.Fatalf("machine1 recovered: %s", out4)
	}
}

func TestMigrateStorage(t *testing.T) {
	e := newTestEnv(t)
	e.gitRun("init")
	e.gitRun("set", "OLD_KEY", "--stdin")
	e.gitRun("tag", "OLD_KEY", "prod")
	remote := e.newBareRemote(t)
	out, code := e.gitRun("migrate", "storage", "--to", "git", "--remote", remote)
	if code != 0 {
		t.Fatalf("migrate storage: %s (%d)", out, code)
	}
	out, _ = e.gitRun("list")
	if !strings.Contains(out, "OLD_KEY") {
		t.Fatalf("migrated secret missing: %s", out)
	}
	if out, code = e.gitRun("export", "--env-file", "verify.env"); code != 0 {
		t.Fatalf("export after migrate: %s (%d)", out, code)
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "work", "verify.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "OLD_KEY=secret-value") {
		t.Fatalf("export content after migrate: %s", string(data))
	}
}

func TestMigrateRejectsBadTags(t *testing.T) {
	e := newTestEnv(t)
	e.gitRun("init")
	e.gitRun("set", "KEY", "--stdin")
	e.gitRun("tag", "KEY", "Prod")
	out, code := e.gitRun("migrate", "storage", "--to", "git", "--remote", e.newBareRemote(t))
	if code == 0 || !strings.Contains(out, "Prod") {
		t.Fatalf("bad tag pre-flight must list offender: %s (%d)", out, code)
	}
}

func TestBareMigrateStillWorks(t *testing.T) {
	e := newTestEnv(t)
	e.gitRun("init")
	e.gitRun("set", "KEY", "--stdin")
	if out, code := e.gitRun("migrate"); code != 0 && !strings.Contains(out, "KDF version") {
		t.Fatalf("bare migrate behavior: %s (%d)", out, code)
	}
}

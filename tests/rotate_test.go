package integration

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}

func (e *testEnv) runWithPassword(t *testing.T, password string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(e.binary, args...)
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD="+password, "HOME="+e.dir)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), exitCode(err)
}

func runRotateStdin(t *testing.T, e *testEnv, oldPassword, newPassword string) (string, int) {
	t.Helper()
	cmd := exec.Command(e.binary, "rotate", "--stdin")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD="+oldPassword, "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte(newPassword + "\n"))
		stdin.Close()
	}()
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String() + errBuf.String(), exitCode(err)
}

func setSecretWithPassword(t *testing.T, e *testEnv, password, name, value string) {
	t.Helper()
	cmd := exec.Command(e.binary, "set", name, "--stdin")
	cmd.Dir = e.dir
	cmd.Env = append(os.Environ(), "PSST_PASSWORD="+password, "HOME="+e.dir)
	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte(value + "\n"))
		stdin.Close()
	}()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("set %s failed: %s", name, out)
	}
}

func TestRotateEndToEnd(t *testing.T) {
	e := newTestEnv(t)
	if _, _, code := e.run("init", "--storage", "git"); code != 0 {
		t.Fatal("git init failed")
	}
	e.setSecret(t, "API_KEY", "secret123")

	out, code := runRotateStdin(t, e, "test-password", "new-password")
	if code != 0 {
		t.Fatalf("rotate failed: %s", out)
	}
	if !strings.Contains(out, "Rotated: 1 secrets re-encrypted") {
		t.Fatalf("summary: %s", out)
	}
	if _, _, code := e.runWithPassword(t, "test-password", "get", "API_KEY", "--storage", "git"); code != 1 {
		t.Fatal("old password must fail after rotation")
	}
	stdout, _, code := e.runWithPassword(t, "new-password", "get", "API_KEY", "--storage", "git")
	if code != 0 || !strings.Contains(stdout, "secret123") {
		t.Fatalf("new password get: %s %d", stdout, code)
	}
}

func TestRotateEmptyStdinAborts(t *testing.T) {
	e := newTestEnv(t)
	e.run("init", "--storage", "git")
	out, code := runRotateStdin(t, e, "test-password", "")
	if code != 1 || !strings.Contains(out, "empty") {
		t.Fatalf("empty stdin = %d %s", code, out)
	}
}

func TestRotateEmptyVault(t *testing.T) {
	e := newTestEnv(t)
	e.run("init", "--storage", "git")
	out, code := runRotateStdin(t, e, "test-password", "new-password")
	if code != 0 {
		t.Fatalf("empty vault rotate = %d %s", code, out)
	}
	if !strings.Contains(out, "vault is empty") {
		t.Fatalf("empty vault note: %s", out)
	}
	setSecretWithPassword(t, e, "new-password", "FIRST", "x")
}

func TestRotateRequiresGit(t *testing.T) {
	e := newTestEnv(t)
	e.initVault()
	e.setSecret(t, "API_KEY", "secret123")
	_, stderr, code := e.run("rotate", "--stdin")
	if code != 1 || !strings.Contains(stderr, "git storage") {
		t.Fatalf("sqlite rotate = %d %s", code, stderr)
	}
}

func TestRotateNoTTYNoStdin(t *testing.T) {
	e := newTestEnv(t)
	e.run("init", "--storage", "git")
	_, stderr, code := e.run("rotate")
	if code != 1 || !strings.Contains(stderr, "--stdin") {
		t.Fatalf("no tty = %d %s", code, stderr)
	}
}

func TestRotatePushFailureRecoveryHint(t *testing.T) {
	e := newTestEnv(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("bare: %v\n%s", err, out)
	}
	e.run("init", "--storage", "git", "--remote", remote)
	e.setSecret(t, "API_KEY", "secret123")
	st, _ := os.Stat(remote)
	if err := os.Chmod(remote, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(remote, st.Mode().Perm()) })
	out, code := runRotateStdin(t, e, "test-password", "new-password")
	if code != 1 || !strings.Contains(out, "psst sync") || !strings.Contains(out, "--discard-local") {
		t.Fatalf("push failure = %d %s", code, out)
	}
	if err := os.Chmod(remote, st.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
}

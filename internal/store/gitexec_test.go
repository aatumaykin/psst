package store

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newBareRemote(t *testing.T) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return remote
}

func TestGitRunnerAllowlist(t *testing.T) {
	dir := t.TempDir()
	g := NewGitRunner(dir)
	if _, err := g.Run("init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := g.Run("status"); err != nil {
		t.Fatalf("status: %v", err)
	}
	if _, err := g.Run("clean", "-fd"); err == nil {
		t.Fatal("clean must be rejected")
	}
	if _, err := g.Run("reset", "--hard", "HEAD"); err == nil {
		t.Fatal("generic reset must be rejected")
	}
	if _, err := g.Run("rebase", "--continue"); err == nil {
		t.Fatal("rebase --continue must be rejected")
	}
	_, err := g.Run("rebase", "--abort")
	if err == nil {
		t.Fatal("rebase --abort runs git and fails without an active rebase")
	}
	if strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("rebase --abort must pass the allowlist: %v", err)
	}
}

func TestGitRunnerEnv(t *testing.T) {
	dir := t.TempDir()
	g := NewGitRunner(dir)
	if _, err := g.Run("init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	out, err := g.Run("config", "--get", "core.hooksPath")
	if err != nil {
		t.Fatalf("config get: %v", err)
	}
	if strings.TrimSpace(out) != "/dev/null" {
		t.Fatalf("hooksPath not enforced: %q", out)
	}
}

func TestRepoLockExclusive(t *testing.T) {
	dir := t.TempDir()
	l1, err := LockRepoWait(dir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := LockRepoWait(dir, 100*time.Millisecond); err == nil {
		t.Fatal("second lock must time out")
	}
	if err := l1.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	l2, err := LockRepoWait(dir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("relock after unlock: %v", err)
	}
	l2.Unlock()
}

package store

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type GitRunner struct{ dir string }

func NewGitRunner(dir string) *GitRunner {
	return &GitRunner{dir: dir}
}

var (
	globalCfgOnce sync.Once
	globalCfgPath string
	globalCfgErr  error
)

func emptyGlobalConfig() (string, error) {
	globalCfgOnce.Do(func() {
		f, err := os.CreateTemp("", "psst-git-global-*")
		if err != nil {
			globalCfgErr = fmt.Errorf("create global config: %w", err)
			return
		}
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			os.Remove(f.Name())
			globalCfgErr = fmt.Errorf("chmod global config: %w", err)
			return
		}
		f.Close()
		globalCfgPath = f.Name()
	})
	return globalCfgPath, globalCfgErr
}

var allowedSubcommands = map[string]bool{
	"clone": true, "init": true, "config": true, "fetch": true,
	"pull": true, "add": true, "rm": true, "mv": true,
	"commit": true, "push": true, "log": true, "show": true,
	"status": true, "checkout": true,
}

func gitEnv() ([]string, error) {
	cfg, err := emptyGlobalConfig()
	if err != nil {
		return nil, err
	}
	env := make([]string, 0, len(os.Environ())+3)
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "GIT_") {
			continue
		}
		env = append(env, e)
	}
	env = append(env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+cfg,
	)
	return env, nil
}

func (g *GitRunner) runGit(args ...string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("git subcommand not allowed: ")
	}
	sub := args[0]
	if !allowedSubcommands[sub] {
		if sub == "rebase" && len(args) > 1 && args[1] == "--abort" {
		} else {
			return "", fmt.Errorf("git subcommand not allowed: %s", sub)
		}
	}
	if _, err := os.Stat(g.dir); err != nil {
		return "", fmt.Errorf("git dir not accessible: %w", err)
	}
	env, err := gitEnv()
	if err != nil {
		return "", err
	}
	full := append([]string{"-c", "core.hooksPath=/dev/null"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = g.dir
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		msg := stderr.String()
		if len(msg) > 512 {
			msg = msg[len(msg)-512:]
		}
		return string(stdout), fmt.Errorf("git %s: %s", sub, msg)
	}
	return string(stdout), nil
}

func (g *GitRunner) Run(args ...string) (stdout string, err error) {
	return g.runGit(args...)
}

func (g *GitRunner) RunOK(args ...string) bool {
	_, err := g.runGit(args...)
	return err == nil
}

func (g *GitRunner) RunResetHardUpstream() error {
	if _, err := os.Stat(g.dir); err != nil {
		return fmt.Errorf("git dir not accessible: %w", err)
	}
	env, err := gitEnv()
	if err != nil {
		return err
	}
	cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", "reset", "--hard", "@{upstream}")
	cmd.Dir = g.dir
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if len(msg) > 512 {
			msg = msg[len(msg)-512:]
		}
		return fmt.Errorf("git reset: %s", msg)
	}
	return nil
}

type RepoLock struct {
	path string
	f    *os.File
}

func LockRepo(repoDir string) (*RepoLock, error) {
	return LockRepoWait(repoDir, 10*time.Second)
}

func LockRepoWait(repoDir string, wait time.Duration) (*RepoLock, error) {
	path := repoDir + "/.psst.lock"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open repo lock: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &RepoLock{path: path, f: f}, nil
		}
		if err != syscall.EWOULDBLOCK {
			f.Close()
			return nil, fmt.Errorf("flock repo: %w", err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("repo is locked by another psst process")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (l *RepoLock) Unlock() error {
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN); err != nil {
		l.f.Close()
		return fmt.Errorf("unlock repo: %w", err)
	}
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("close repo lock: %w", err)
	}
	return nil
}

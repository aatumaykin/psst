package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	gitCfgFilePerm    = 0o600
	gitEnvExtraVars   = 3
	stderrTailLimit   = 512
	lockWait          = 10 * time.Second
	lockRetryInterval = 50 * time.Millisecond
)

type GitRunner struct{ dir string }

func NewGitRunner(dir string) *GitRunner {
	return &GitRunner{dir: dir}
}

var (
	globalCfgOnce sync.Once
	globalCfgPath string
	errGlobalCfg  error
)

func emptyGlobalConfig() (string, error) {
	globalCfgOnce.Do(func() {
		f, err := os.CreateTemp("", "psst-git-global-*")
		if err != nil {
			errGlobalCfg = fmt.Errorf("create global config: %w", err)
			return
		}
		if err = f.Chmod(gitCfgFilePerm); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			errGlobalCfg = fmt.Errorf("chmod global config: %w", err)
			return
		}
		_ = f.Close()
		globalCfgPath = f.Name()
	})
	return globalCfgPath, errGlobalCfg
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
	env := make([]string, 0, len(os.Environ())+gitEnvExtraVars)
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
		return "", errors.New("git subcommand not allowed: ")
	}
	sub := args[0]
	rebaseAbort := sub == "rebase" && len(args) > 1 && args[1] == "--abort"
	if !allowedSubcommands[sub] && !rebaseAbort {
		return "", fmt.Errorf("git subcommand not allowed: %s", sub)
	}
	if _, err := os.Stat(g.dir); err != nil {
		return "", fmt.Errorf("git dir not accessible: %w", err)
	}
	env, err := gitEnv()
	if err != nil {
		return "", err
	}
	full := append([]string{"-c", "core.hooksPath=/dev/null"}, args...)
	cmd := exec.CommandContext(context.Background(), "git", full...)
	cmd.Dir = g.dir
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		msg := stderr.String()
		if len(msg) > stderrTailLimit {
			msg = msg[len(msg)-stderrTailLimit:]
		}
		return string(stdout), fmt.Errorf("git %s: %s", sub, msg)
	}
	return string(stdout), nil
}

func (g *GitRunner) Run(args ...string) (string, error) {
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
	cmd := exec.CommandContext(
		context.Background(),
		"git",
		"-c",
		"core.hooksPath=/dev/null",
		"reset",
		"--hard",
		"@{upstream}",
	)
	cmd.Dir = g.dir
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		msg := stderr.String()
		if len(msg) > stderrTailLimit {
			msg = msg[len(msg)-stderrTailLimit:]
		}
		return fmt.Errorf("git reset: %s", msg)
	}
	return nil
}

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var envNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func FindVaultPath(global bool, env string) (string, error) {
	if env != "" && !envNameRegex.MatchString(env) {
		return "", fmt.Errorf("invalid env name %q: must match %s", env, envNameRegex.String())
	}

	baseDir := ".psst"
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home dir: %w", err)
		}
		baseDir = filepath.Join(home, ".psst")
	}

	if env != "" {
		baseDir = filepath.Join(baseDir, "envs", env)
	}

	return filepath.Join(baseDir, "vault.db"), nil
}

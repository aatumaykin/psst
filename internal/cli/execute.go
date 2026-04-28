package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/aatumaykin/psst/internal/runner"
	"github.com/aatumaykin/psst/internal/vault"
)

type execConfig struct {
	JSONOut    bool
	Quiet      bool
	Global     bool
	Env        string
	Tags       []string
	NoMask     bool
	ExpandArgs bool
}

func execWithSecrets(
	ctx context.Context,
	v vault.Interface,
	secretNames []string,
	commandArgs []string,
	cfg execConfig,
) error {
	var secrets map[string][]byte
	var err error

	switch {
	case len(cfg.Tags) > 0:
		secrets, err = v.GetSecretsByTagValues(ctx, cfg.Tags)
	case len(secretNames) > 0:
		for _, name := range secretNames {
			if validErr := requireValidName(name); validErr != nil {
				return validErr
			}
		}
		secrets = make(map[string][]byte, len(secretNames))
		for _, name := range secretNames {
			sec, getErr := v.GetSecret(ctx, name)
			if getErr != nil {
				return exitWithError(getErr.Error())
			}
			secrets[name] = sec.Value
		}
	default:
		secrets, err = v.GetAllSecrets(ctx)
	}
	if err != nil {
		return exitWithError(err.Error())
	}
	defer zeroSecretMap(secrets)

	if len(secrets) == 0 {
		return exitWithError("No secrets available")
	}

	if cfg.NoMask {
		fmt.Fprintln(os.Stderr, "Warning: output masking is disabled, secrets may appear in output")
	}
	if cfg.ExpandArgs {
		fmt.Fprintln(os.Stderr,
			"Warning: secret expansion in arguments is enabled, values may be visible in /proc/PID/cmdline")
	}

	r := getRunner()
	code, runErr := r.Exec(secrets, commandArgs[0], commandArgs[1:], runner.ExecOptions{
		MaskOutput: !cfg.NoMask,
		ExpandArgs: cfg.ExpandArgs,
	})
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "Command failed: %v\n", runErr)
	}
	if code != 0 {
		return &exitError{code: code}
	}
	return nil
}

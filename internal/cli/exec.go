package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/aatumaykin/psst/internal/runner"
	"github.com/aatumaykin/psst/internal/vault"
)

type ExecConfig struct {
	JSONOut bool
	Quiet   bool
	Global  bool
	Env     string
	Tags    []string
	NoMask  bool
}

func handleExecPatternDirect(
	ctx context.Context,
	secretNames []string,
	commandArgs []string,
	cfg ExecConfig,
) error {
	v, err := getUnlockedVault(ctx, cfg.JSONOut, cfg.Quiet, cfg.Global, cfg.Env)
	if err != nil {
		return err
	}
	defer v.Close()

	secrets := make(map[string][]byte)

	if len(cfg.Tags) > 0 {
		names, tagErr := v.GetSecretNamesByTags(ctx, cfg.Tags)
		if tagErr != nil {
			return exitWithError(tagErr.Error())
		}
		secretNames = append(secretNames, names...)
	}

	for _, name := range secretNames {
		if nameErr := vault.ValidateSecretName(name); nameErr != nil {
			return exitWithError(fmt.Sprintf("Invalid secret name %q", name))
		}
	}

	for _, name := range secretNames {
		sec, getErr := v.GetSecret(ctx, name)
		if getErr != nil {
			return exitWithError(getErr.Error())
		}
		secrets[name] = sec.Value
	}

	r := getRunner()
	maskOutput := !cfg.NoMask
	code, execErr := r.Exec(secrets, commandArgs[0], commandArgs[1:], runner.ExecOptions{MaskOutput: maskOutput})
	if execErr != nil {
		fmt.Fprintf(os.Stderr, "Command failed: %v\n", execErr)
	}
	if code != 0 {
		return &exitError{code: code}
	}
	return nil
}

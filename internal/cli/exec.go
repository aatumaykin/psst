package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/aatumaykin/psst/internal/runner"
)

func handleExecPatternDirect(
	ctx context.Context,
	secretNames []string,
	commandArgs []string,
	jsonOut, quiet, global bool,
	env string,
	tags []string,
	noMask bool,
) error {
	v, err := getUnlockedVault(ctx, jsonOut, quiet, global, env)
	if err != nil {
		return err
	}
	defer v.Close()

	secrets := make(map[string][]byte)

	if len(tags) > 0 {
		names, tagErr := v.GetSecretNamesByTags(ctx, tags)
		if tagErr != nil {
			return exitWithError(tagErr.Error())
		}
		secretNames = append(secretNames, names...)
	}

	for _, name := range secretNames {
		if !validName.MatchString(name) {
			return exitWithError(fmt.Sprintf("Invalid secret name %q. Must match [A-Z][A-Z0-9_]*", name))
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
	maskOutput := !noMask
	code, execErr := r.Exec(secrets, commandArgs[0], commandArgs[1:], runner.ExecOptions{MaskOutput: maskOutput})
	if execErr != nil {
		fmt.Fprintf(os.Stderr, "Command failed: %v\n", execErr)
	}
	if code != 0 {
		return &exitError{code: code}
	}
	return nil
}

package cli

import (
	"fmt"
	"os"

	"github.com/aatumaykin/psst/internal/runner"
)

func handleExecPatternDirect(
	secretNames []string,
	commandArgs []string,
	jsonOut, quiet, global bool,
	env string,
	tags []string,
	noMask bool,
) error {
	v, err := getUnlockedVault(jsonOut, quiet, global, env)
	if err != nil {
		return err
	}
	defer v.Close()

	secrets := make(map[string][]byte)

	if len(tags) > 0 {
		names, tagErr := v.GetSecretNamesByTags(tags)
		if tagErr != nil {
			return exitWithError(tagErr.Error())
		}
		secretNames = append(secretNames, names...)
	}

	for _, name := range secretNames {
		sec, getErr := v.GetSecret(name)
		if getErr != nil {
			return exitWithError(getErr.Error())
		}
		if sec != nil {
			secrets[name] = sec.Value
		} else if !quiet {
			fmt.Fprintf(os.Stderr, "Warning: secret %q not found\n", name)
		}
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

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
) int {
	v, err := getUnlockedVault(jsonOut, quiet, global, env)
	if err != nil {
		exitWithError(err.Error())
	}
	defer v.Close()

	secrets := make(map[string]string)

	if len(tags) > 0 {
		names, tagErr := v.GetSecretNamesByTags(tags)
		if tagErr != nil {
			exitWithError(tagErr.Error())
		}
		secretNames = append(secretNames, names...)
	}

	for _, name := range secretNames {
		sec, getErr := v.GetSecret(name)
		if getErr != nil {
			exitWithError(getErr.Error())
		}
		if sec != nil {
			secrets[name] = sec.Value
		}
	}

	r := getRunner()
	maskOutput := !noMask
	code, execErr := r.Exec(secrets, commandArgs[0], commandArgs[1:], runner.ExecOptions{MaskOutput: maskOutput})
	if execErr != nil {
		fmt.Fprintf(os.Stderr, "Command failed: %v\n", execErr)
	}
	return code
}

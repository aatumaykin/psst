package cli

import "github.com/aatumaykin/psst/internal/runner"

func handleExecPatternDirect(secretNames []string, commandArgs []string, jsonOut, quiet, global bool, env string, tags []string, noMask bool) {
	v, err := getUnlockedVault(jsonOut, quiet, global, env)
	if err != nil {
		exitWithError(err.Error())
	}
	defer v.Close()

	secrets := make(map[string]string)

	if len(tags) > 0 {
		names, err := v.GetSecretNamesByTags(tags)
		if err != nil {
			exitWithError(err.Error())
		}
		secretNames = append(secretNames, names...)
	}

	for _, name := range secretNames {
		sec, err := v.GetSecret(name)
		if err != nil {
			exitWithError(err.Error())
		}
		if sec != nil {
			secrets[name] = sec.Value
		}
	}

	r := getRunner()
	maskOutput := !noMask
	code, err := r.Exec(secrets, commandArgs[0], commandArgs[1:], runner.ExecOptions{MaskOutput: maskOutput})
	if err != nil {
		exitWithError(err.Error())
	}

	if code != 0 {
		exitWithError("command exited with non-zero code")
	}
}

package cli

import (
	"context"
)

type ExecConfig = execConfig

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

	return execWithSecrets(ctx, v, secretNames, commandArgs, cfg)
}

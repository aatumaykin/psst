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
	v, err := getUnlockedVault(ctx, cfg.JSONOut, cfg.Quiet, globalConfig{
		Global:    cfg.Global,
		Env:       cfg.Env,
		VaultPath: cfg.VaultPath,
	})
	if err != nil {
		return err
	}
	defer v.Close()

	return execWithSecrets(ctx, v, secretNames, commandArgs, cfg)
}

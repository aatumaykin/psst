package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/runner"
	"github.com/aatumaykin/psst/internal/vault"
)

type exitError struct {
	code int
}

func (e *exitError) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

var rootCmd = &cobra.Command{
	Use:           "psst",
	Short:         "AI-native secrets manager",
	Long:          "Because your agent doesn't need to know your secrets.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	args := os.Args[1:]

	dashDashIdx := -1
	for i, a := range args {
		if a == "--" {
			dashDashIdx = i
			break
		}
	}

	if dashDashIdx >= 0 {
		cfg := parseGlobalFlagsFromArgs(args[:dashDashIdx])
		secretNames := filterSecretNames(args[:dashDashIdx])
		secretNames = filterSubcommandNames(secretNames)
		commandArgs := args[dashDashIdx+1:]

		if len(commandArgs) > 0 && (len(secretNames) > 0 || len(cfg.Tags) > 0) {
			noMask := containsFlag(args, "--no-mask")
			expandArgs := containsFlag(args, "--expand-args")
			err := handleExecPatternDirect(
				context.Background(),
				secretNames, commandArgs,
				ExecConfig{
					JSONOut:    cfg.JSON,
					Quiet:      cfg.Quiet,
					Global:     cfg.Global,
					Env:        cfg.Env,
					Tags:       cfg.Tags,
					NoMask:     noMask,
					ExpandArgs: expandArgs,
				},
			)
			var exitErr *exitError
			if err != nil && errors.As(err, &exitErr) {
				os.Exit(exitErr.code)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			return nil
		}
	}

	err := rootCmd.Execute()
	var exitErr *exitError
	if err != nil && errors.As(err, &exitErr) {
		os.Exit(exitErr.code)
	}
	return err
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.PersistentFlags().Bool("json", false, "JSON output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Quiet mode")
	rootCmd.PersistentFlags().BoolP("global", "g", false, "Use global vault")
	rootCmd.PersistentFlags().String("env", "", "Environment name")
	rootCmd.PersistentFlags().StringArray("tag", nil, "Filter by tag (repeatable)")
}

type globalConfig struct {
	JSON   bool
	Quiet  bool
	Global bool
	Env    string
	Tags   []string
}

func resolveEnvOverrides(cfg *globalConfig) {
	if os.Getenv("PSST_GLOBAL") == "1" {
		cfg.Global = true
	}
	if cfg.Env == "" {
		cfg.Env = os.Getenv("PSST_ENV")
	}
}

func getGlobalFlags(cmd *cobra.Command) globalConfig {
	cfg := globalConfig{}
	cfg.JSON, _ = cmd.Flags().GetBool("json")
	cfg.Quiet, _ = cmd.Flags().GetBool("quiet")
	cfg.Global, _ = cmd.Flags().GetBool("global")
	cfg.Env, _ = cmd.Flags().GetString("env")
	cfg.Tags, _ = cmd.Flags().GetStringArray("tag")
	resolveEnvOverrides(&cfg)
	return cfg
}

func getFormatter(jsonOut, quiet bool) *output.Formatter {
	return output.NewFormatter(jsonOut, quiet)
}

func getRunner() *runner.Runner {
	return runner.New()
}

const (
	ExitNoVault    = 3
	ExitAuthFailed = 5
)

func getUnlockedVault(ctx context.Context, jsonOut, quiet, global bool, env string) (vault.Interface, error) {
	vaultPath, err := vault.FindVaultPath(global, env)
	if err != nil {
		return nil, err
	}

	if _, statErr := os.Stat(vaultPath); os.IsNotExist(statErr) {
		printNoVault(jsonOut, quiet)
		return nil, &exitError{code: ExitNoVault}
	}

	v, err := vault.Open(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}

	if unlockErr := v.Unlock(ctx); unlockErr != nil {
		_ = v.Close()
		printAuthFailed(jsonOut, quiet)
		return nil, &exitError{code: ExitAuthFailed}
	}
	return v, nil
}

func printNoVault(jsonOut, quiet bool) {
	f := output.NewFormatter(jsonOut, quiet)
	f.Error("No vault found. Run `psst init` to create one.")
}

func printAuthFailed(jsonOut, quiet bool) {
	f := output.NewFormatter(jsonOut, quiet)
	if keyring.IsKeychainAvailable() {
		f.Error("Failed to unlock vault. Check keychain access.")
	} else {
		f.Error(
			"Failed to unlock vault. Set PSST_PASSWORD:\n" +
				"  export PSST_PASSWORD=\"your-password\"\n" +
				"  Note: PSST_PASSWORD is visible to other users via /proc on shared systems",
		)
	}
}

func withVault(cmd *cobra.Command, fn func(v vault.Interface, f *output.Formatter) error) error {
	cfg := getGlobalFlags(cmd)
	v, err := getUnlockedVault(cmd.Context(), cfg.JSON, cfg.Quiet, cfg.Global, cfg.Env)
	if err != nil {
		return err
	}
	defer v.Close()
	f := getFormatter(cfg.JSON, cfg.Quiet)
	return fn(v, f)
}

func zeroSecretMap(m map[string][]byte) {
	for k, v := range m {
		crypto.ZeroBytes(v)
		delete(m, k)
	}
}

func exitWithError(msg string) error {
	fmt.Fprintf(os.Stderr, "✗ %s\n", msg)
	return &exitError{code: 1}
}

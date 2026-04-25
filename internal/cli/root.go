package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/runner"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

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
		jsonOut, quiet, global, env, tags := parseGlobalFlagsFromArgs(args[:dashDashIdx])
		secretNames := filterSecretNames(args[:dashDashIdx], jsonOut, quiet, global, env, tags)
		secretNames = filterSubcommandNames(secretNames)
		commandArgs := args[dashDashIdx+1:]

		if len(commandArgs) > 0 && (len(secretNames) > 0 || len(tags) > 0) {
			noMask := containsFlag(args, "--no-mask")
			os.Exit(handleExecPatternDirect(
				secretNames, commandArgs,
				jsonOut, quiet, global, env, tags, noMask,
			))
		}
	}

	return rootCmd.Execute()
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.PersistentFlags().Bool("json", false, "JSON output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Quiet mode")
	rootCmd.PersistentFlags().BoolP("global", "g", false, "Use global vault")
	rootCmd.PersistentFlags().String("env", "", "Environment name")
	rootCmd.PersistentFlags().StringArray("tag", nil, "Filter by tag (repeatable)")
}

func getGlobalFlags(cmd *cobra.Command) (bool, bool, bool, string, []string) {
	jsonOut, _ := cmd.Flags().GetBool("json")
	quiet, _ := cmd.Flags().GetBool("quiet")
	global, _ := cmd.Flags().GetBool("global")
	env, _ := cmd.Flags().GetString("env")
	tags, _ := cmd.Flags().GetStringArray("tag")

	if os.Getenv("PSST_GLOBAL") == "1" {
		global = true
	}
	if env == "" {
		env = os.Getenv("PSST_ENV")
	}
	return jsonOut, quiet, global, env, tags
}

func getFormatter(jsonOut, quiet bool) *output.Formatter {
	return output.NewFormatter(jsonOut, quiet)
}

func getRunner() *runner.Runner {
	return runner.New()
}

func createDependencies() (crypto.Encryptor, keyring.KeyProvider) {
	enc := crypto.NewAESGCM()
	kp := keyring.NewProvider(enc)
	return enc, kp
}

func getUnlockedVault(jsonOut, quiet, global bool, env string) (*vault.Vault, error) {
	vaultPath, err := vault.FindVaultPath(global, env)
	if err != nil {
		return nil, err
	}

	//nolint:gosec // user-provided path is intentional for CLI tool
	if _, statErr := os.Stat(vaultPath); os.IsNotExist(statErr) {
		printNoVault(jsonOut, quiet)
		//nolint:mnd // exit code for missing vault
		os.Exit(3)
	}

	enc, kp := createDependencies()

	s, err := store.NewSQLite(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}

	if schemaErr := s.InitSchema(); schemaErr != nil {
		_ = s.Close()
		return nil, fmt.Errorf("init schema: %w", schemaErr)
	}

	v := vault.New(enc, kp, s)
	if unlockErr := v.Unlock(); unlockErr != nil {
		_ = s.Close()
		printAuthFailed(jsonOut, quiet)
		//nolint:mnd // exit code for auth failure
		os.Exit(5)
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
		f.Error("Failed to unlock vault. Set PSST_PASSWORD:\n  export PSST_PASSWORD=\"your-password\"\n  Note: PSST_PASSWORD is visible to other users via /proc on shared systems")
	}
}

func exitWithError(msg string) {
	fmt.Fprintf(os.Stderr, "✗ %s\n", msg)
	os.Exit(1)
}

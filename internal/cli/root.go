package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
	rootCmd.PersistentFlags().String("storage", "", "Storage backend: sqlite or git")
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

func getStorageFlag(cmd *cobra.Command) string {
	storage, _ := cmd.Flags().GetString("storage")
	if storage == "" {
		storage = os.Getenv("PSST_STORAGE")
	}
	return storage
}

func storageIsGit(cmd *cobra.Command, global bool, env string) bool {
	envDir, err := vault.FindVaultDir(global, env)
	if err != nil {
		return false
	}
	storage, err := ResolveStorage(getStorageFlag(cmd), envDir)
	return err == nil && storage == "git"
}

func getUnlockedVault(cmd *cobra.Command, jsonOut, quiet bool, global bool, env string) (*vault.Vault, error) {
	envDir, err := vault.FindVaultDir(global, env)
	if err != nil {
		return nil, err
	}

	storage, err := ResolveStorage(getStorageFlag(cmd), envDir)
	if err != nil {
		return nil, err
	}

	//nolint:gosec // user-provided path is intentional for CLI tool
	dbExists := statExists(vault.SQLitePath(envDir))
	gitMarkerExists := statExists(filepath.Join(envDir, "repo", "psst.yaml")) ||
		statExists(filepath.Join(envDir, "repo", ".git"))
	if storage == "git" {
		if !statExists(filepath.Join(envDir, "repo", ".git")) {
			printNoVault(jsonOut, quiet)
			//nolint:mnd // exit code for missing vault
			os.Exit(3)
		}
	} else if !dbExists && !gitMarkerExists {
		printNoVault(jsonOut, quiet)
		//nolint:mnd // exit code for missing vault
		os.Exit(3)
	}

	enc := crypto.NewAESGCM()

	s, _, err := OpenVaultStore(envDir, storage, "", false)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}

	if schemaErr := s.InitSchema(); schemaErr != nil {
		_ = s.Close()
		if errors.Is(schemaErr, store.ErrSaltChanged) || errors.Is(schemaErr, store.ErrKDFWeakened) {
			exitWithError(fmt.Sprintf("vault metadata changed since last open: %v; see rotation procedure in docs", schemaErr))
		}
		return nil, fmt.Errorf("init schema: %w", schemaErr)
	}

	var kp keyring.KeyProvider
	if storage == "git" {
		kp = keyring.NewPasswordProvider(enc, true)
	} else {
		kp = keyring.NewProvider(enc)
	}

	v := vault.New(enc, kp, s)
	if unlockErr := v.Unlock(); unlockErr != nil {
		_ = s.Close()
		if storage == "git" {
			f := output.NewFormatter(jsonOut, quiet)
			f.Error("Failed to unlock vault. Set PSST_PASSWORD or run in a terminal")
		} else {
			printAuthFailed(jsonOut, quiet)
		}
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

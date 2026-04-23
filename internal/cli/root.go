package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/runner"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
)

var rootCmd = &cobra.Command{
	Use:          "psst",
	Short:        "AI-native secrets manager",
	Long:         "Because your agent doesn't need to know your secrets.",
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
		commandArgs := args[dashDashIdx+1:]

		if len(commandArgs) > 0 && (len(secretNames) > 0 || len(tags) > 0) {
			noMask := containsFlag(args, "--no-mask")
			handleExecPatternDirect(secretNames, commandArgs, jsonOut, quiet, global, env, tags, noMask)
			return nil
		}
	}

	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().Bool("json", false, "JSON output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Quiet mode")
	rootCmd.PersistentFlags().BoolP("global", "g", false, "Use global vault")
	rootCmd.PersistentFlags().String("env", "", "Environment name")
	rootCmd.PersistentFlags().StringArray("tag", nil, "Filter by tag (repeatable)")
}

func getGlobalFlags(cmd *cobra.Command) (jsonOut, quiet, global bool, env string, tags []string) {
	jsonOut, _ = cmd.Flags().GetBool("json")
	quiet, _ = cmd.Flags().GetBool("quiet")
	global, _ = cmd.Flags().GetBool("global")
	env, _ = cmd.Flags().GetString("env")
	tags, _ = cmd.Flags().GetStringArray("tag")

	if os.Getenv("PSST_GLOBAL") == "1" {
		global = true
	}
	if env == "" {
		env = os.Getenv("PSST_ENV")
	}
	return
}

func getFormatter(jsonOut, quiet bool) *output.Formatter {
	return output.NewFormatter(jsonOut, quiet)
}

func getRunner() *runner.Runner {
	return runner.New()
}

func getUnlockedVault(jsonOut, quiet, global bool, env string) (*vault.Vault, error) {
	vaultPath, err := vault.FindVaultPath(global, env)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		printNoVault(jsonOut, quiet)
		os.Exit(3)
	}

	enc := crypto.NewAESGCM()
	kp := keyring.NewProvider(enc)

	s, err := store.NewSQLite(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}

	v := vault.New(enc, kp, s)
	if err := v.Unlock(); err != nil {
		s.Close()
		printAuthFailed(jsonOut, quiet)
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
		f.Error("Failed to unlock vault. Set PSST_PASSWORD:\n  export PSST_PASSWORD=\"your-password\"")
	}
}

func exitWithError(msg string) {
	fmt.Fprintf(os.Stderr, "✗ %s\n", msg)
	os.Exit(1)
}

func parseGlobalFlagsFromArgs(args []string) (jsonOut, quiet, global bool, env string, tags []string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--quiet", "-q":
			quiet = true
		case "--global", "-g":
			global = true
		case "--env":
			i++
			if i < len(args) {
				env = args[i]
			}
		case "--tag":
			i++
			if i < len(args) {
				tags = append(tags, args[i])
			}
		}
	}
	if os.Getenv("PSST_GLOBAL") == "1" {
		global = true
	}
	if env == "" {
		env = os.Getenv("PSST_ENV")
	}
	return
}

func filterSecretNames(args []string, jsonOut, quiet, global bool, env string, tags []string) []string {
	skip := map[string]bool{"--json": true, "--quiet": true, "-q": true, "--global": true, "-g": true, "--no-mask": true}
	var names []string
	for _, a := range args {
		if skip[a] || a == "--env" || a == "--tag" || a == env {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	return names
}

func containsFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

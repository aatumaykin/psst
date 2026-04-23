package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "psst",
	Short:        "AI-native secrets manager",
	Long:         "Because your agent doesn't need to know your secrets.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().Bool("json", false, "JSON output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Quiet mode")
	rootCmd.PersistentFlags().BoolP("global", "g", false, "Use global vault")
	rootCmd.PersistentFlags().String("env", "", "Environment name")
	rootCmd.PersistentFlags().StringArray("tag", nil, "Filter by tag (repeatable)")
}

func getGlobalFlags(cmd *cobra.Command) (jsonOutput, quiet, global bool, env string, tags []string) {
	jsonOutput, _ = cmd.Flags().GetBool("json")
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

func exitWithError(msg string) {
	fmt.Fprintf(os.Stderr, "✗ %s\n", msg)
	os.Exit(1)
}

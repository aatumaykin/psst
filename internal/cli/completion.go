package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [shell]",
	Short: "Generate shell completion script",
	Long: `Generate shell completion script for psst.

Supported shells:
  zsh    Zsh (oh-my-zsh, prezto, standalone)

Examples:
  psst completion zsh > ~/.zfunc/_psst
  psst completion zsh > "${fpath[1]}/_psst"
  psst completion zsh > ~/.oh-my-zsh/custom/plugins/psst/psst.plugin.zsh`,
	Args:              cobra.ExactArgs(1),
	ValidArgs:         []string{"zsh"},
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		default:
			return fmt.Errorf("unsupported shell: %s (supported: zsh)", args[0])
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}

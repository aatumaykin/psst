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
  bash       Bash
  fish       Fish
  powershell PowerShell
  zsh        Zsh (oh-my-zsh, prezto, standalone)

Examples:
  psst completion bash > /etc/bash_completion.d/psst
  psst completion fish > ~/.config/fish/completions/psst.fish
  psst completion powershell > psst-completion.ps1
  psst completion zsh > ~/.zfunc/_psst
  psst completion zsh > "${fpath[1]}/_psst"
  psst completion zsh > ~/.oh-my-zsh/custom/plugins/psst/psst.plugin.zsh`,
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"bash", "fish", "powershell", "zsh"},
	RunE: func(_ *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		default:
			return fmt.Errorf("unsupported shell: %s (supported: bash, fish, powershell, zsh)", args[0])
		}
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(completionCmd)
}

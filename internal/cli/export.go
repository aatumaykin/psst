package cli

import (
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets in .env format",
	RunE: func(cmd *cobra.Command, _ []string) error {
		envFile, _ := cmd.Flags().GetString("env-file")
		return withVault(cmd, func(v vault.VaultInterface, f *output.Formatter) error {
			secrets, err := v.GetAllSecrets(cmd.Context())
			if err != nil {
				return exitWithError(err.Error())
			}

			strSecrets := make(map[string]string, len(secrets))
			for k, v := range secrets {
				strSecrets[k] = string(v)
			}

			if envFile != "" {
				if runtime.GOOS != "windows" {
					if info, statErr := os.Lstat(envFile); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
						return exitWithError("Refusing to write to symlink: " + envFile)
					}
				}
				file, fileErr := os.OpenFile(envFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				if fileErr != nil {
					return exitWithError("Cannot create file: " + fileErr.Error())
				}
				defer file.Close()
				f.EnvListWriter(strSecrets, file)
			} else {
				f.EnvListWriter(strSecrets, os.Stdout)
			}

			if !f.IsQuiet() && !f.IsJSON() {
				f.Success("Secrets exported")
			}
			return nil
		})
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	exportCmd.Flags().String("env-file", "", "Write to file instead of stdout")
	rootCmd.AddCommand(exportCmd)
}

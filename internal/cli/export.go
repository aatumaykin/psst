package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets in .env format",
	RunE: func(cmd *cobra.Command, _ []string) error {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		envFile, _ := cmd.Flags().GetString("env-file")

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			return err
		}
		defer v.Close()

		secrets, err := v.GetAllSecrets()
		if err != nil {
			return exitWithError(err.Error())
		}

		strSecrets := make(map[string]string, len(secrets))
		for k, v := range secrets {
			strSecrets[k] = string(v)
		}

		if envFile != "" {
			if info, statErr := os.Lstat(envFile); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
				return exitWithError("Refusing to write to symlink: " + envFile)
			}
			file, fileErr := os.OpenFile(envFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if fileErr != nil {
				return exitWithError("Cannot create file: " + fileErr.Error())
			}
			defer file.Close()
			f.EnvListWriter(strSecrets, file)
		} else {
			if jsonOut {
				f.EnvList(strSecrets)
			} else {
				f.EnvListWriter(strSecrets, os.Stdout)
			}
		}

		if !quiet && !jsonOut {
			f.Success("Secrets exported")
		}
		return nil
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	exportCmd.Flags().String("env-file", "", "Write to file instead of stdout")
	rootCmd.AddCommand(exportCmd)
}

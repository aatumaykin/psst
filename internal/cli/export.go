package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets in .env format",
	Run: func(cmd *cobra.Command, _ []string) {
		jsonOut, quiet, global, env, _ := getGlobalFlags(cmd)
		f := getFormatter(jsonOut, quiet)
		envFile, _ := cmd.Flags().GetString("env-file")

		v, err := getUnlockedVault(jsonOut, quiet, global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		defer v.Close()

		secrets, err := v.GetAllSecrets()
		if err != nil {
			exitWithError(err.Error())
		}

		if envFile != "" {
			file, fileErr := os.OpenFile(envFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if fileErr != nil {
				exitWithError("Cannot create file: " + fileErr.Error())
			}
			defer file.Close()
			f.EnvListWriter(secrets, file)
		} else {
			if jsonOut {
				f.EnvList(secrets)
			} else {
				f.EnvListWriter(secrets, os.Stdout)
			}
		}

		if !quiet && !jsonOut {
			f.Success("Secrets exported")
		}
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	exportCmd.Flags().String("env-file", "", "Write to file instead of stdout")
	rootCmd.AddCommand(exportCmd)
}

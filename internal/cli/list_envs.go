package cli

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var listEnvsCmd = &cobra.Command{
	Use:   "list-envs",
	Short: "List all environments",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := getGlobalFlags(cmd)
		f := getFormatter(cfg.JSON, cfg.Quiet)

		var envs []string

		localEnvsDir := filepath.Join(".psst", "envs")
		envs = append(envs, scanEnvDir(localEnvsDir)...)

		home, err := os.UserHomeDir()
		if err == nil {
			globalEnvsDir := filepath.Join(home, ".psst", "envs")
			envs = append(envs, scanEnvDir(globalEnvsDir)...)
		}

		deduped := dedupe(envs)
		f.EnvironmentList(deduped)
		return nil
	},
}

func scanEnvDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var envs []string
	for _, e := range entries {
		if e.IsDir() {
			dbPath := filepath.Join(dir, e.Name(), "vault.db")
			if _, statErr := os.Stat(dbPath); statErr == nil {
				envs = append(envs, e.Name())
			}
		}
	}
	return envs
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(listEnvsCmd)
}

package cli

import (
	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/output"
	"github.com/aatumaykin/psst/internal/vault"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg := getGlobalFlags(cmd)
		return withVault(cmd, func(v vault.Interface, f *output.Formatter) error {
			if len(cfg.Tags) > 0 {
				filtered, tagErr := v.GetSecretsByTags(cmd.Context(), cfg.Tags)
				if tagErr != nil {
					return exitWithError(tagErr.Error())
				}
				f.SecretList(toSecretItems(filtered))
				return nil
			}

			secrets, err := v.ListSecrets(cmd.Context())
			if err != nil {
				return exitWithError(err.Error())
			}
			f.SecretList(toSecretItems(secrets))
			return nil
		})
	},
}

func toSecretItems(metas []vault.SecretMeta) []output.SecretItem {
	items := make([]output.SecretItem, len(metas))
	for i, m := range metas {
		items[i] = output.SecretItem{
			Name:      m.Name,
			Tags:      m.Tags,
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		}
	}
	return items
}

//nolint:gochecknoinits // cobra command registration
func init() {
	rootCmd.AddCommand(listCmd)
}

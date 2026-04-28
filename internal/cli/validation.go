package cli

import (
	"fmt"

	"github.com/aatumaykin/psst/internal/vault"
)

func requireValidName(name string) error {
	if err := vault.ValidateSecretName(name); err != nil {
		return exitWithError(fmt.Sprintf("Invalid secret name %q", name))
	}
	return nil
}

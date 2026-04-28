package vault

import (
	"context"
	"fmt"

	"github.com/aatumaykin/psst/internal/store"
)

func maxVersion(history []store.HistoryEntry) int {
	maxV := 0
	for _, h := range history {
		if h.Version > maxV {
			maxV = h.Version
		}
	}
	return maxV
}

func (v *Vault) GetHistory(ctx context.Context, name string) ([]SecretHistoryEntry, error) {
	var result []SecretHistoryEntry
	err := v.withRLock(func() error {
		entries, histErr := v.store.GetHistory(ctx, name)
		if histErr != nil {
			return histErr
		}
		result = make([]SecretHistoryEntry, len(entries))
		for i, e := range entries {
			result[i] = SecretHistoryEntry{
				Version:    e.Version,
				Tags:       e.Tags,
				ArchivedAt: e.ArchivedAt,
			}
		}
		return nil
	})
	return result, err
}

func (v *Vault) Rollback(ctx context.Context, name string, version int) error {
	return v.withRLock(func() error {
		return v.store.ExecTx(func() error {
			current, err := v.store.GetSecret(ctx, name)
			if err != nil {
				return err
			}
			if current == nil {
				return fmt.Errorf("secret %q not found", name)
			}

			history, err := v.store.GetHistory(ctx, name)
			if err != nil {
				return err
			}

			var target *store.HistoryEntry
			for i := range history {
				if history[i].Version == version {
					target = &history[i]
					break
				}
			}
			if target == nil {
				return fmt.Errorf("version %d not found", version)
			}

			newVersion := maxVersion(history) + 1
			if err = v.store.AddHistory(
				ctx,
				name,
				newVersion,
				current.EncryptedValue,
				current.IV,
				current.Tags,
			); err != nil {
				return fmt.Errorf("archive history: %w", err)
			}
			if err = v.store.PruneHistory(ctx, name, maxHistory); err != nil {
				return fmt.Errorf("prune history: %w", err)
			}
			return v.store.SetSecret(ctx, name, target.EncryptedValue, target.IV, target.Tags)
		})
	})
}

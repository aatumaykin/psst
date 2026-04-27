package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/store"
)

func (v *Vault) SetSecret(ctx context.Context, name string, value []byte, tags []string) error {
	key, err := v.copyKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)

	if err := ValidateSecretName(name); err != nil {
		return err
	}
	if len(value) > maxSecretValueLen {
		return fmt.Errorf("secret value too long: max %d bytes", maxSecretValueLen)
	}
	if err := ValidateTags(tags); err != nil {
		return err
	}

	return v.store.ExecTx(func() error {
		existing, err := v.store.GetSecret(ctx, name)
		if err != nil {
			return fmt.Errorf("get existing secret: %w", err)
		}
		if existing != nil {
			var history []store.HistoryEntry
			history, err = v.store.GetHistory(ctx, name)
			if err != nil {
				return fmt.Errorf("get history: %w", err)
			}
			version := maxVersion(history) + 1
			if err = v.store.AddHistory(ctx,
				name, version,
				existing.EncryptedValue, existing.IV, existing.Tags,
			); err != nil {
				return fmt.Errorf("archive history: %w", err)
			}
			if err = v.store.PruneHistory(ctx, name, maxHistory); err != nil {
				return fmt.Errorf("prune history: %w", err)
			}
		}

		ciphertext, iv, err := v.enc.Encrypt(value, key)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		return v.store.SetSecret(ctx, name, ciphertext, iv, tags)
	})
}

var ErrSecretNotFound = errors.New("secret not found")

func (v *Vault) GetSecret(ctx context.Context, name string) (*Secret, error) {
	key, err := v.copyKey()
	if err != nil {
		return nil, err
	}

	stored, err := v.store.GetSecret(ctx, name)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, ErrSecretNotFound
	}

	plaintext, err := v.enc.Decrypt(stored.EncryptedValue, stored.IV, key)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return &Secret{
		Name:      stored.Name,
		Value:     plaintext,
		Tags:      stored.Tags,
		CreatedAt: stored.CreatedAt,
		UpdatedAt: stored.UpdatedAt,
	}, nil
}

func (v *Vault) ListSecrets(ctx context.Context) ([]SecretMeta, error) {
	if err := v.requireUnlock(); err != nil {
		return nil, err
	}
	storeMetas, err := v.store.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]SecretMeta, len(storeMetas))
	for i, m := range storeMetas {
		result[i] = SecretMeta{
			Name:      m.Name,
			Tags:      m.Tags,
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		}
	}
	return result, nil
}

func (v *Vault) DeleteSecret(ctx context.Context, name string) error {
	if err := v.requireUnlock(); err != nil {
		return err
	}
	return v.store.ExecTx(func() error {
		if err := v.store.DeleteSecret(ctx, name); err != nil {
			return err
		}
		return v.store.DeleteHistory(ctx, name)
	})
}

func (v *Vault) GetAllSecrets(ctx context.Context) (map[string][]byte, error) {
	key, err := v.copyKey()
	if err != nil {
		return nil, err
	}

	all, err := v.store.GetAllSecrets(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte, len(all))
	for _, s := range all {
		var plaintext []byte
		plaintext, err = v.enc.Decrypt(s.EncryptedValue, s.IV, key)
		if err != nil {
			for k, v := range result {
				crypto.ZeroBytes(v)
				delete(result, k)
			}
			return nil, fmt.Errorf("decrypt secret: %w", err)
		}
		result[s.Name] = plaintext
	}
	return result, nil
}

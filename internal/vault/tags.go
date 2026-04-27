package vault

import (
	"context"
	"fmt"
	"slices"
)

func (v *Vault) AddTag(ctx context.Context, name string, tag string) error {
	if err := v.requireUnlock(); err != nil {
		return err
	}

	return v.store.ExecTx(func() error {
		sec, err := v.store.GetSecret(ctx, name)
		if err != nil {
			return err
		}
		if sec == nil {
			return fmt.Errorf("secret %q not found", name)
		}

		if slices.Contains(sec.Tags, tag) {
			return nil
		}
		sec.Tags = append(sec.Tags, tag)
		return v.store.SetSecret(ctx, name, sec.EncryptedValue, sec.IV, sec.Tags)
	})
}

func (v *Vault) RemoveTag(ctx context.Context, name string, tag string) error {
	if err := v.requireUnlock(); err != nil {
		return err
	}

	return v.store.ExecTx(func() error {
		sec, err := v.store.GetSecret(ctx, name)
		if err != nil {
			return err
		}
		if sec == nil {
			return fmt.Errorf("secret %q not found", name)
		}

		filtered := make([]string, 0, len(sec.Tags))
		for _, t := range sec.Tags {
			if t != tag {
				filtered = append(filtered, t)
			}
		}
		sec.Tags = filtered
		return v.store.SetSecret(ctx, name, sec.EncryptedValue, sec.IV, sec.Tags)
	})
}

func (v *Vault) GetSecretsByTags(ctx context.Context, tags []string) ([]SecretMeta, error) {
	all, err := v.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}

	if len(tags) == 0 {
		return all, nil
	}

	var result []SecretMeta
	for _, s := range all {
		for _, wantTag := range tags {
			if slices.Contains(s.Tags, wantTag) {
				result = append(result, s)
				break
			}
		}
	}
	return result, nil
}

func (v *Vault) GetSecretNamesByTags(ctx context.Context, tags []string) ([]string, error) {
	metas, err := v.GetSecretsByTags(ctx, tags)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(metas))
	for i, m := range metas {
		names[i] = m.Name
	}
	return names, nil
}

func (v *Vault) GetSecretsByTagValues(ctx context.Context, tags []string) (map[string][]byte, error) {
	names, err := v.GetSecretNamesByTags(ctx, tags)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return map[string][]byte{}, nil
	}

	all, err := v.GetAllSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("get secrets: %w", err)
	}

	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}

	result := make(map[string][]byte, len(names))
	for name, val := range all {
		if nameSet[name] {
			result[name] = val
		}
	}
	return result, nil
}

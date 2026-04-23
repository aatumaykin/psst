package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/user/psst/internal/crypto"
	"github.com/user/psst/internal/keyring"
	"github.com/user/psst/internal/store"
)

const (
	serviceName = "psst"
	accountName = "vault-key"
	maxHistory  = 10
)

type Vault struct {
	enc   *crypto.AESGCM
	kp    keyring.KeyProvider
	store *store.SQLiteStore
	key   []byte
}

func New(enc *crypto.AESGCM, kp keyring.KeyProvider, s *store.SQLiteStore) *Vault {
	return &Vault{enc: enc, kp: kp, store: s}
}

func FindVaultPath(global bool, env string) (string, error) {
	baseDir := ".psst"
	if global {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home dir: %w", err)
		}
		baseDir = filepath.Join(home, ".psst")
	}

	if env != "" {
		baseDir = filepath.Join(baseDir, "envs", env)
	}

	return filepath.Join(baseDir, "vault.db"), nil
}

func InitVault(vaultPath string, enc *crypto.AESGCM, kp keyring.KeyProvider, opts InitOptions) error {
	dir := filepath.Dir(vaultPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	s, err := store.NewSQLite(vaultPath)
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	defer s.Close()

	if err := s.InitSchema(); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}

	if !opts.SkipKeychain {
		key, err := kp.GenerateKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		if err := kp.SetKey(serviceName, accountName, key); err != nil {
			return fmt.Errorf("store key in keychain: %w", err)
		}
	}

	return nil
}

func (v *Vault) Unlock() error {
	key, err := v.kp.GetKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}
	v.key = key
	return nil
}

func (v *Vault) SetSecret(name string, value string, tags []string) error {
	if v.key == nil {
		return fmt.Errorf("vault is locked")
	}

	existing, _ := v.store.GetSecret(name)
	if existing != nil {
		history, _ := v.store.GetHistory(name)
		version := len(history) + 1
		v.store.AddHistory(name, version, existing.EncryptedValue, existing.IV, existing.Tags)
		v.store.PruneHistory(name, maxHistory)
	}

	ciphertext, iv, err := v.enc.Encrypt([]byte(value), v.key)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	return v.store.SetSecret(name, ciphertext, iv, tags)
}

func (v *Vault) GetSecret(name string) (*Secret, error) {
	if v.key == nil {
		return nil, fmt.Errorf("vault is locked")
	}

	stored, err := v.store.GetSecret(name)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, nil
	}

	plaintext, err := v.enc.Decrypt(stored.EncryptedValue, stored.IV, v.key)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return &Secret{
		Name:      stored.Name,
		Value:     string(plaintext),
		Tags:      stored.Tags,
		CreatedAt: stored.CreatedAt,
		UpdatedAt: stored.UpdatedAt,
	}, nil
}

func (v *Vault) ListSecrets() ([]SecretMeta, error) {
	metas, err := v.store.ListSecrets()
	if err != nil {
		return nil, err
	}
	result := make([]SecretMeta, len(metas))
	for i, m := range metas {
		result[i] = SecretMeta{
			Name:      m.Name,
			Tags:      m.Tags,
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		}
	}
	return result, nil
}

func (v *Vault) DeleteSecret(name string) error {
	if err := v.store.DeleteSecret(name); err != nil {
		return err
	}
	return v.store.DeleteHistory(name)
}

func (v *Vault) GetHistory(name string) ([]SecretHistoryEntry, error) {
	entries, err := v.store.GetHistory(name)
	if err != nil {
		return nil, err
	}
	result := make([]SecretHistoryEntry, len(entries))
	for i, e := range entries {
		result[i] = SecretHistoryEntry{
			Version:    e.Version,
			Tags:       e.Tags,
			ArchivedAt: e.ArchivedAt,
		}
	}
	return result, nil
}

func (v *Vault) Rollback(name string, version int) error {
	if v.key == nil {
		return fmt.Errorf("vault is locked")
	}

	current, err := v.store.GetSecret(name)
	if err != nil {
		return err
	}
	if current == nil {
		return fmt.Errorf("secret %q not found", name)
	}

	history, err := v.store.GetHistory(name)
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

	newVersion := len(history) + 1
	v.store.AddHistory(name, newVersion, current.EncryptedValue, current.IV, current.Tags)

	return v.store.SetSecret(name, target.EncryptedValue, target.IV, target.Tags)
}

func (v *Vault) AddTag(name string, tag string) error {
	sec, err := v.store.GetSecret(name)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("secret %q not found", name)
	}

	for _, t := range sec.Tags {
		if t == tag {
			return nil
		}
	}
	sec.Tags = append(sec.Tags, tag)
	return v.store.SetSecret(name, sec.EncryptedValue, sec.IV, sec.Tags)
}

func (v *Vault) RemoveTag(name string, tag string) error {
	sec, err := v.store.GetSecret(name)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("secret %q not found", name)
	}

	filtered := sec.Tags[:0]
	for _, t := range sec.Tags {
		if t != tag {
			filtered = append(filtered, t)
		}
	}
	sec.Tags = filtered
	return v.store.SetSecret(name, sec.EncryptedValue, sec.IV, sec.Tags)
}

func (v *Vault) GetSecretsByTags(tags []string) ([]SecretMeta, error) {
	all, err := v.ListSecrets()
	if err != nil {
		return nil, err
	}

	if len(tags) == 0 {
		return all, nil
	}

	var result []SecretMeta
	for _, s := range all {
		for _, wantTag := range tags {
			for _, hasTag := range s.Tags {
				if wantTag == hasTag {
					result = append(result, s)
					goto next
				}
			}
		}
	next:
	}
	return result, nil
}

func (v *Vault) GetAllSecrets() (map[string]string, error) {
	if v.key == nil {
		return nil, fmt.Errorf("vault is locked")
	}

	metas, err := v.store.ListSecrets()
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(metas))
	for _, m := range metas {
		stored, err := v.store.GetSecret(m.Name)
		if err != nil {
			return nil, err
		}
		plaintext, err := v.enc.Decrypt(stored.EncryptedValue, stored.IV, v.key)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", m.Name, err)
		}
		result[m.Name] = string(plaintext)
	}
	return result, nil
}

func (v *Vault) GetSecretNamesByTags(tags []string) ([]string, error) {
	metas, err := v.GetSecretsByTags(tags)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(metas))
	for i, m := range metas {
		names[i] = m.Name
	}
	return names, nil
}

func (v *Vault) Close() error {
	return v.store.Close()
}

func parseTagsJSON(jsonStr string) []string {
	var tags []string
	json.Unmarshal([]byte(jsonStr), &tags)
	return tags
}

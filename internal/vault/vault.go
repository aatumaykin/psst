package vault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)

type Vault struct {
	enc   crypto.Encryptor
	kp    keyring.KeyProvider
	store store.SecretStore
	key   []byte
}

const (
	serviceName = "psst"
	accountName = "vault-key"
	maxHistory  = 10
	saltSize    = 16
)

func New(enc crypto.Encryptor, kp keyring.KeyProvider, s store.SecretStore) *Vault {
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

func InitVault(vaultPath string, _ crypto.Encryptor, kp keyring.KeyProvider, opts InitOptions) error {
	dir := filepath.Dir(vaultPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	s, err := store.NewSQLite(vaultPath)
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	defer s.Close()

	if err = s.InitSchema(); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}

	if err = s.SetMeta("kdf_version", strconv.Itoa(crypto.CurrentKDFVersion)); err != nil {
		return fmt.Errorf("set vault metadata: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err = rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	if err = s.SetMeta("kdf_salt", base64.StdEncoding.EncodeToString(salt)); err != nil {
		return fmt.Errorf("set kdf salt: %w", err)
	}

	if !opts.SkipKeychain && !keyring.IsEnvProvider(kp) {
		var key []byte
		key, err = kp.GenerateKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		if err = kp.SetKey(serviceName, accountName, key); err != nil {
			return fmt.Errorf("store key in keychain: %w", err)
		}
	}

	return nil
}

func (v *Vault) Unlock() error {
	rawKey, err := v.kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}

	kdfVersion, err := v.readKDFVersion()
	if err != nil {
		return err
	}
	var key []byte
	switch kdfVersion {
	case crypto.KDFVersion2:
		saltB64, metaErr := v.store.GetMeta("kdf_salt")
		if metaErr != nil {
			return fmt.Errorf("get kdf_salt: %w", metaErr)
		}
		if saltB64 != "" {
			salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
			if decodeErr != nil {
				return fmt.Errorf("decode kdf_salt: %w", decodeErr)
			}
			key, err = v.enc.KeyToBufferV2WithSalt(rawKey, salt)
		} else {
			key, err = v.enc.KeyToBufferV2(rawKey)
		}
	default:
		key, err = v.enc.KeyToBuffer(rawKey)
	}
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	v.key = key
	return nil
}

func (v *Vault) readKDFVersion() (int, error) {
	val, err := v.store.GetMeta("kdf_version")
	if err != nil {
		return 0, fmt.Errorf("get kdf_version: %w", err)
	}
	if val == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 1, nil //nolint:nilerr // unrecognized version defaults to V1
	}
	return n, nil
}

func (v *Vault) SetSecret(name string, value []byte, tags []string) error {
	if v.key == nil {
		return errors.New("vault is locked")
	}

	return v.store.ExecTx(func() error {
		existing, err := v.store.GetSecret(name)
		if err != nil {
			return fmt.Errorf("get existing secret: %w", err)
		}
		if existing != nil {
			var history []store.HistoryEntry
			history, err = v.store.GetHistory(name)
			if err != nil {
				return fmt.Errorf("get history: %w", err)
			}
			maxVersion := 0
			for _, h := range history {
				if h.Version > maxVersion {
					maxVersion = h.Version
				}
			}
			version := maxVersion + 1
			if err = v.store.AddHistory(
				name, version,
				existing.EncryptedValue, existing.IV, existing.Tags,
			); err != nil {
				return fmt.Errorf("archive history: %w", err)
			}
			if err = v.store.PruneHistory(name, maxHistory); err != nil {
				return fmt.Errorf("prune history: %w", err)
			}
		}

		ciphertext, iv, err := v.enc.Encrypt(value, v.key)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		return v.store.SetSecret(name, ciphertext, iv, tags)
	})
}

var ErrSecretNotFound = errors.New("secret not found")

func (v *Vault) GetSecret(name string) (*Secret, error) {
	if v.key == nil {
		return nil, errors.New("vault is locked")
	}

	stored, err := v.store.GetSecret(name)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, ErrSecretNotFound
	}

	plaintext, err := v.enc.Decrypt(stored.EncryptedValue, stored.IV, v.key)
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

func (v *Vault) ListSecrets() ([]SecretMeta, error) {
	storeMetas, err := v.store.ListSecrets()
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

func (v *Vault) DeleteSecret(name string) error {
	return v.store.ExecTx(func() error {
		if err := v.store.DeleteSecret(name); err != nil {
			return err
		}
		return v.store.DeleteHistory(name)
	})
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
		return errors.New("vault is locked")
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

	return v.store.ExecTx(func() error {
		maxVersion := 0
		for _, h := range history {
			if h.Version > maxVersion {
				maxVersion = h.Version
			}
		}
		newVersion := maxVersion + 1
		if err = v.store.AddHistory(name, newVersion, current.EncryptedValue, current.IV, current.Tags); err != nil {
			return fmt.Errorf("archive history: %w", err)
		}
		if err = v.store.PruneHistory(name, maxHistory); err != nil {
			return fmt.Errorf("prune history: %w", err)
		}
		return v.store.SetSecret(name, target.EncryptedValue, target.IV, target.Tags)
	})
}

func (v *Vault) AddTag(name string, tag string) error {
	sec, err := v.store.GetSecret(name)
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

	filtered := make([]string, 0, len(sec.Tags))
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
			if slices.Contains(s.Tags, wantTag) {
				result = append(result, s)
				break
			}
		}
	}
	return result, nil
}

func (v *Vault) GetAllSecrets() (map[string][]byte, error) {
	if v.key == nil {
		return nil, errors.New("vault is locked")
	}

	all, err := v.store.GetAllSecrets()
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte, len(all))
	for _, s := range all {
		var plaintext []byte
		plaintext, err = v.enc.Decrypt(s.EncryptedValue, s.IV, v.key)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret: %w", err)
		}
		result[s.Name] = plaintext
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

func (v *Vault) GetSecretsByTagValues(tags []string) (map[string][]byte, error) {
	names, err := v.GetSecretNamesByTags(tags)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]byte, len(names))
	for _, name := range names {
		sec, secErr := v.GetSecret(name)
		if secErr != nil {
			return nil, fmt.Errorf("get secret: %w", secErr)
		}
		result[name] = sec.Value
	}
	return result, nil
}

func (v *Vault) Close() error {
	for i := range v.key {
		v.key[i] = 0
	}
	v.key = nil
	return v.store.Close()
}

func (v *Vault) MigrateKDF() error {
	if v.key == nil {
		return errors.New("vault is locked")
	}

	all, err := v.store.GetAllSecrets()
	if err != nil {
		return fmt.Errorf("get secrets: %w", err)
	}

	rawKey, err := v.kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("get raw key: %w", err)
	}

	saltB64, err := v.store.GetMeta("kdf_salt")
	if err != nil {
		return fmt.Errorf("get kdf_salt: %w", err)
	}
	if saltB64 == "" {
		salt := make([]byte, saltSize)
		if _, err = rand.Read(salt); err != nil {
			return fmt.Errorf("generate salt: %w", err)
		}
		saltB64 = base64.StdEncoding.EncodeToString(salt)
	}
	salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
	if decodeErr != nil {
		return fmt.Errorf("decode kdf_salt: %w", decodeErr)
	}
	newKey, err := v.enc.KeyToBufferV2WithSalt(rawKey, salt)
	if err != nil {
		return fmt.Errorf("derive key with salt: %w", err)
	}

	if txErr := v.store.ExecTx(func() error {
		for _, s := range all {
			var plaintext []byte
			plaintext, err = v.enc.Decrypt(s.EncryptedValue, s.IV, v.key)
			if err != nil {
				return fmt.Errorf("decrypt secret: %w", err)
			}
			var ciphertext, iv []byte
			ciphertext, iv, err = v.enc.Encrypt(plaintext, newKey)
			for i := range plaintext {
				plaintext[i] = 0
			}
			if err != nil {
				return fmt.Errorf("encrypt secret: %w", err)
			}
			err = v.store.SetSecret(s.Name, ciphertext, iv, s.Tags)
			if err != nil {
				return fmt.Errorf("update secret: %w", err)
			}
		}
		if metaErr := v.store.SetMeta("kdf_salt", saltB64); metaErr != nil {
			return fmt.Errorf("store kdf_salt: %w", metaErr)
		}
		return v.store.SetMeta("kdf_version", strconv.Itoa(crypto.CurrentKDFVersion))
	}); txErr != nil {
		return txErr
	}
	for i := range v.key {
		v.key[i] = 0
	}
	v.key = newKey
	return nil
}

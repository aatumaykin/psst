package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

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
	serviceName       = "psst"
	accountName       = "vault-key"
	maxHistory        = 10
	saltSize          = 16
	maxSecretNameLen  = 256
	maxSecretValueLen = 4096

	maxUnlockAttempts     = 10
	unlockDelayBaseMs     = 500
	metaUnlockAttempts    = "unlock_attempts"
	metaUnlockLockedUntil = "unlock_locked_until"
)

var secretNameRegex = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

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

func InitVault(
	ctx context.Context,
	vaultPath string,
	enc crypto.Encryptor,
	kp keyring.KeyProvider,
	opts InitOptions,
) error {
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

	if err = s.SetMeta(ctx, "kdf_version", strconv.Itoa(crypto.CurrentKDFVersion)); err != nil {
		return fmt.Errorf("set vault metadata: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err = rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	if err = s.SetMeta(ctx, "kdf_salt", base64.StdEncoding.EncodeToString(salt)); err != nil {
		return fmt.Errorf("set kdf salt: %w", err)
	}

	var rawKey string
	if !opts.SkipKeychain && !keyring.IsEnvProvider(kp) {
		var key []byte
		key, err = kp.GenerateKey()
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		if err = kp.SetKey(serviceName, accountName, key); err != nil {
			return fmt.Errorf("store key in keychain: %w", err)
		}
		rawKey = hex.EncodeToString(key)
	} else {
		rawKey, err = kp.GetRawKey(serviceName, accountName)
		if err != nil {
			return nil
		}
	}

	derivedKey, deriveErr := enc.KeyToBufferV2WithSalt(rawKey, salt)
	if deriveErr != nil {
		return fmt.Errorf("derive verification key: %w", deriveErr)
	}

	verifyCiphertext, verifyIV, encErr := enc.Encrypt([]byte("psst-verify"), derivedKey)
	if encErr != nil {
		return fmt.Errorf("create verification: %w", encErr)
	}

	if metaErr := s.SetMeta(ctx, "verify_iv", base64.StdEncoding.EncodeToString(verifyIV)); metaErr != nil {
		return fmt.Errorf("set verify_iv: %w", metaErr)
	}
	if metaErr := s.SetMeta(ctx, "verify_data", base64.StdEncoding.EncodeToString(verifyCiphertext)); metaErr != nil {
		return fmt.Errorf("set verify_data: %w", metaErr)
	}

	return nil
}

func (v *Vault) Unlock(ctx context.Context) error {
	if lockedUntil, _ := v.store.GetMeta(ctx, metaUnlockLockedUntil); lockedUntil != "" {
		ts, parseErr := time.Parse(time.RFC3339, lockedUntil)
		if parseErr == nil && time.Now().Before(ts) {
			return fmt.Errorf("vault locked until %s due to too many failed unlock attempts", ts.Format(time.Kitchen))
		}
	}

	rawKey, err := v.kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("unlock vault: %w", err)
	}

	kdfVersion, err := v.readKDFVersion(ctx)
	if err != nil {
		return err
	}
	var key []byte
	switch kdfVersion {
	case 1:
		key, err = v.enc.KeyToBuffer(rawKey)
	case crypto.KDFVersion2:
		var saltB64 string
		saltB64, metaErr := v.store.GetMeta(ctx, "kdf_salt")
		if metaErr != nil {
			return fmt.Errorf("get kdf_salt: %w", metaErr)
		}
		if saltB64 == "" {
			return errors.New("vault corrupted: kdf_salt missing for V2 vault")
		}
		var salt []byte
		salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
		if decodeErr != nil {
			return fmt.Errorf("decode kdf_salt: %w", decodeErr)
		}
		key, err = v.enc.KeyToBufferV2WithSalt(rawKey, salt)
	default:
		return fmt.Errorf("unsupported KDF version: %d", kdfVersion)
	}
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	v.key = key

	all, verifyErr := v.store.GetAllSecrets(ctx)
	if verifyErr != nil {
		crypto.ZeroBytes(v.key)
		v.key = nil
		return fmt.Errorf("verify vault: %w", verifyErr)
	}

	verifyIV, ivErr := v.store.GetMeta(ctx, "verify_iv")
	verifyData, dataErr := v.store.GetMeta(ctx, "verify_data")

	if ivErr == nil && dataErr == nil && verifyIV != "" && verifyData != "" {
		ivBytes, _ := base64.StdEncoding.DecodeString(verifyIV)
		dataBytes, _ := base64.StdEncoding.DecodeString(verifyData)
		_, decErr := v.enc.Decrypt(dataBytes, ivBytes, v.key)
		if decErr != nil {
			attempts, _ := v.store.IncrementMetaInt(ctx, metaUnlockAttempts, 1)
			if attempts >= maxUnlockAttempts {
				lockDuration := time.Duration(attempts*unlockDelayBaseMs) * time.Millisecond
				lockedUntil := time.Now().Add(lockDuration)
				_ = v.store.SetMeta(ctx, metaUnlockLockedUntil, lockedUntil.Format(time.RFC3339))
				_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
			}
			crypto.ZeroBytes(v.key)
			v.key = nil
			return errors.New("authentication failed")
		}
	} else if len(all) > 0 {
		_, decErr := v.enc.Decrypt(all[0].EncryptedValue, all[0].IV, v.key)
		if decErr != nil {
			attempts, _ := v.store.IncrementMetaInt(ctx, metaUnlockAttempts, 1)
			if attempts >= maxUnlockAttempts {
				lockDuration := time.Duration(attempts*unlockDelayBaseMs) * time.Millisecond
				lockedUntil := time.Now().Add(lockDuration)
				_ = v.store.SetMeta(ctx, metaUnlockLockedUntil, lockedUntil.Format(time.RFC3339))
				_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
			}
			crypto.ZeroBytes(v.key)
			v.key = nil
			return errors.New("authentication failed")
		}
	}

	_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
	_ = v.store.SetMeta(ctx, metaUnlockLockedUntil, "")
	return nil
}

func (v *Vault) readKDFVersion(ctx context.Context) (int, error) {
	val, err := v.store.GetMeta(ctx, "kdf_version")
	if err != nil {
		return 0, fmt.Errorf("get kdf_version: %w", err)
	}
	if val == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("corrupted kdf_version: %q: %w", val, err)
	}
	if n < 1 || n > 2 {
		return 0, fmt.Errorf("unsupported KDF version: %d", n)
	}
	return n, nil
}

func (v *Vault) SetSecret(ctx context.Context, name string, value []byte, tags []string) error {
	if v.key == nil {
		return errors.New("vault is locked")
	}

	if len(name) > maxSecretNameLen {
		return fmt.Errorf("secret name too long: max %d bytes", maxSecretNameLen)
	}
	if !secretNameRegex.MatchString(name) {
		return fmt.Errorf("invalid secret name %q: must match ^[A-Z][A-Z0-9_]*$", name)
	}
	if len(value) > maxSecretValueLen {
		return fmt.Errorf("secret value too long: max %d bytes", maxSecretValueLen)
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
			maxVersion := 0
			for _, h := range history {
				if h.Version > maxVersion {
					maxVersion = h.Version
				}
			}
			version := maxVersion + 1
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

		ciphertext, iv, err := v.enc.Encrypt(value, v.key)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		return v.store.SetSecret(ctx, name, ciphertext, iv, tags)
	})
}

var ErrSecretNotFound = errors.New("secret not found")

func (v *Vault) GetSecret(ctx context.Context, name string) (*Secret, error) {
	if v.key == nil {
		return nil, errors.New("vault is locked")
	}

	stored, err := v.store.GetSecret(ctx, name)
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

func (v *Vault) GetHistory(ctx context.Context, name string) ([]SecretHistoryEntry, error) {
	if err := v.requireUnlock(); err != nil {
		return nil, err
	}
	entries, err := v.store.GetHistory(ctx, name)
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

func (v *Vault) Rollback(ctx context.Context, name string, version int) error {
	if v.key == nil {
		return errors.New("vault is locked")
	}

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

	return v.store.ExecTx(func() error {
		maxVersion := 0
		for _, h := range history {
			if h.Version > maxVersion {
				maxVersion = h.Version
			}
		}
		newVersion := maxVersion + 1
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
}

func (v *Vault) AddTag(ctx context.Context, name string, tag string) error {
	if err := v.requireUnlock(); err != nil {
		return err
	}
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
}

func (v *Vault) RemoveTag(ctx context.Context, name string, tag string) error {
	if err := v.requireUnlock(); err != nil {
		return err
	}
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

func (v *Vault) GetAllSecrets(ctx context.Context) (map[string][]byte, error) {
	if v.key == nil {
		return nil, errors.New("vault is locked")
	}

	all, err := v.store.GetAllSecrets(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte, len(all))
	for _, s := range all {
		var plaintext []byte
		plaintext, err = v.enc.Decrypt(s.EncryptedValue, s.IV, v.key)
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
	result := make(map[string][]byte, len(names))
	for _, name := range names {
		sec, secErr := v.GetSecret(ctx, name)
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

func (v *Vault) requireUnlock() error {
	if v.key == nil {
		return fmt.Errorf("vault is locked: unlock required")
	}
	return nil
}

func (v *Vault) MigrateKDF(ctx context.Context) error {
	if v.key == nil {
		return errors.New("vault is locked")
	}

	all, err := v.store.GetAllSecrets(ctx)
	if err != nil {
		return fmt.Errorf("get secrets: %w", err)
	}

	rawKey, err := v.kp.GetRawKey(serviceName, accountName)
	if err != nil {
		return fmt.Errorf("get raw key: %w", err)
	}

	saltB64, err := v.store.GetMeta(ctx, "kdf_salt")
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
			err = v.store.SetSecret(ctx, s.Name, ciphertext, iv, s.Tags)
			if err != nil {
				return fmt.Errorf("update secret: %w", err)
			}
		}
		if metaErr := v.store.SetMeta(ctx, "kdf_salt", saltB64); metaErr != nil {
			return fmt.Errorf("store kdf_salt: %w", metaErr)
		}
		return v.store.SetMeta(ctx, "kdf_version", strconv.Itoa(crypto.CurrentKDFVersion))
	}); txErr != nil {
		crypto.ZeroBytes(newKey)
		return txErr
	}
	for i := range v.key {
		v.key[i] = 0
	}
	v.key = newKey
	return nil
}

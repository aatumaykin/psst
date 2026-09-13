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
	"github.com/aatumaykin/psst/internal/kdf"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)

type Vault struct {
	enc   crypto.Encryptor
	kp    keyring.KeyProvider
	store store.SecretStore
	key   []byte
	aad   []byte
}

const (
	serviceName = "psst"
	accountName = "vault-key"
	maxHistory  = 10
)

func New(enc crypto.Encryptor, kp keyring.KeyProvider, s store.SecretStore) *Vault {
	return &Vault{enc: enc, kp: kp, store: s}
}

func FindVaultDir(global bool, env string) (string, error) {
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

	return baseDir, nil
}

func SQLitePath(dir string) string {
	return filepath.Join(dir, "vault.db")
}

func FindVaultPath(global bool, env string) (string, error) {
	dir, err := FindVaultDir(global, env)
	if err != nil {
		return "", err
	}
	return SQLitePath(dir), nil
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

	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	if err = s.SetMeta("kdf_salt", base64.StdEncoding.EncodeToString(salt)); err != nil {
		return fmt.Errorf("set kdf salt: %w", err)
	}

	if !opts.SkipKeychain {
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

	var key []byte
	if timeStr, _ := v.store.GetMeta("kdf_time"); timeStr != "" {
		saltB64, _ := v.store.GetMeta("kdf_salt")
		salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
		if decodeErr != nil {
			return fmt.Errorf("decode kdf_salt: %w", decodeErr)
		}
		params := crypto.KDFParams{
			Time:    uint32(metaAtoi(v.store, "kdf_time")),
			Memory:  uint32(metaAtoi(v.store, "kdf_memory")),
			Threads: uint8(metaAtoi(v.store, "kdf_threads")),
		}
		key, err = v.enc.DeriveKeyFromPassword(rawKey, salt, params)
		if err != nil {
			return fmt.Errorf("derive key: %w", err)
		}
		v.key = key
		if aadStr, _ := v.store.GetMeta("vault_aad"); aadStr != "" {
			v.aad = []byte(aadStr)
		}
		if gs, ok := v.store.(*store.GitStore); ok {
			gs.SetUnlockedFingerprint(saltB64 + "|" + timeStr + "|" +
				strconv.FormatUint(uint64(params.Memory), 10) + "|" + strconv.FormatUint(uint64(params.Threads), 10))
		}
		return nil
	}

	kdfVersion := v.readKDFVersion()
	switch kdfVersion {
	case crypto.KDFVersion2:
		saltB64, _ := v.store.GetMeta("kdf_salt")
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

func metaAtoi(s store.SecretStore, key string) int {
	val, _ := s.GetMeta(key)
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0
	}
	return n
}

func (v *Vault) encrypt(plaintext []byte) ([]byte, []byte, error) {
	if v.aad != nil {
		return v.enc.EncryptWithAAD(plaintext, v.key, v.aad)
	}
	return v.enc.Encrypt(plaintext, v.key)
}

func (v *Vault) decrypt(ciphertext, iv []byte) ([]byte, error) {
	if v.aad != nil {
		return v.enc.DecryptWithAAD(ciphertext, iv, v.key, v.aad)
	}
	return v.enc.Decrypt(ciphertext, iv, v.key)
}

func (v *Vault) readKDFVersion() int {
	val, _ := v.store.GetMeta("kdf_version")
	if val == "" {
		return 1
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 1
	}
	return n
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
			version := len(history) + 1
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

		ciphertext, iv, err := v.encrypt(value)
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

	plaintext, err := v.decrypt(stored.EncryptedValue, stored.IV)
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
			UpdatedBy: m.UpdatedBy,
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
			Author:     e.Author,
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

	plaintext, err := v.decrypt(target.EncryptedValue, target.IV)
	if err != nil {
		return fmt.Errorf("version %d predates a KDF migration", version)
	}

	return v.store.ExecTx(func() error {
		newVersion := len(history) + 1
		if err = v.store.AddHistory(name, newVersion, current.EncryptedValue, current.IV, current.Tags); err != nil {
			return fmt.Errorf("archive history: %w", err)
		}
		return v.SetSecret(name, plaintext, target.Tags)
	})
}

func (v *Vault) RetagSecret(name string, tags []string) error {
	sec, err := v.store.GetSecret(name)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("secret %q not found", name)
	}
	return v.store.ExecTx(func() error {
		return v.store.SetSecret(name, sec.EncryptedValue, sec.IV, tags)
	})
}

func (v *Vault) Batch(fn func() error) error {
	return v.store.ExecTx(fn)
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
		plaintext, err = v.decrypt(s.EncryptedValue, s.IV)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", s.Name, err)
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

func (v *Vault) Close() error {
	for i := range v.key {
		v.key[i] = 0
	}
	v.key = nil
	return v.store.Close()
}

func (v *Vault) VerifyAllDecryptable() error {
	all, err := v.store.GetAllSecrets()
	if err != nil {
		return fmt.Errorf("get secrets: %w", err)
	}
	for _, s := range all {
		plaintext, err := v.decrypt(s.EncryptedValue, s.IV)
		if err != nil {
			return fmt.Errorf("secret %s is undecryptable under the current key", s.Name)
		}
		for i := range plaintext {
			plaintext[i] = 0
		}
	}
	return nil
}

func (v *Vault) Rotate(newPassword string, params *kdf.Params) (int, error) {
	if v.key == nil {
		return 0, errors.New("vault is locked")
	}
	gs, ok := v.store.(*store.GitStore)
	if !ok {
		return 0, errors.New("rotate requires git storage")
	}
	current := crypto.KDFParams{
		Time:    uint32(metaAtoi(v.store, "kdf_time")),
		Memory:  uint32(metaAtoi(v.store, "kdf_memory")),
		Threads: uint8(metaAtoi(v.store, "kdf_threads")),
	}
	target := current
	if params != nil {
		if params.Time < current.Time || params.Memory < current.Memory || params.Threads < current.Threads {
			return 0, errors.New("rotation must not weaken KDF parameters")
		}
		target = *params
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return 0, fmt.Errorf("generate salt: %w", err)
	}
	newSaltB64 := base64.StdEncoding.EncodeToString(salt)
	newKey, err := v.enc.DeriveKeyFromPassword(newPassword, salt, target)
	if err != nil {
		return 0, fmt.Errorf("derive key: %w", err)
	}
	newAAD := []byte("psst:v1:argon2id:" + newSaltB64)
	rotated := 0
	success := false
	defer func() {
		if !success {
			for i := range newKey {
				newKey[i] = 0
			}
		}
	}()
	err = gs.ExecTxMsg("psst: rotate", func() error {
		all, err := v.store.GetAllSecrets()
		if err != nil {
			return fmt.Errorf("get secrets: %w", err)
		}
		for _, s := range all {
			plaintext, derr := v.decrypt(s.EncryptedValue, s.IV)
			if derr != nil {
				return fmt.Errorf("secret %s is undecryptable under the current key", s.Name)
			}
			var ct, iv []byte
			ct, iv, derr = v.enc.EncryptWithAAD(plaintext, newKey, newAAD)
			for i := range plaintext {
				plaintext[i] = 0
			}
			if derr != nil {
				return fmt.Errorf("encrypt %s: %w", s.Name, derr)
			}
			if err := v.store.SetSecret(s.Name, ct, iv, s.Tags); err != nil {
				return fmt.Errorf("update %s: %w", s.Name, err)
			}
			rotated++
		}
		if params != nil {
			if err := v.store.SetMeta("kdf_time", strconv.Itoa(int(target.Time))); err != nil {
				return fmt.Errorf("set kdf_time: %w", err)
			}
			if err := v.store.SetMeta("kdf_memory", strconv.Itoa(int(target.Memory))); err != nil {
				return fmt.Errorf("set kdf_memory: %w", err)
			}
			if err := v.store.SetMeta("kdf_threads", strconv.Itoa(int(target.Threads))); err != nil {
				return fmt.Errorf("set kdf_threads: %w", err)
			}
		}
		return gs.RotateSalt(newSaltB64)
	})
	if err != nil {
		return rotated, err
	}
	success = true
	v.key = newKey
	v.aad = newAAD
	gs.SetUnlockedFingerprint(gs.FingerprintOfCurrent())
	return rotated, nil
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

	newKey, err := v.enc.KeyToBufferV2(rawKey)
	if err != nil {
		return fmt.Errorf("derive new key: %w", err)
	}

	if timeStr, _ := v.store.GetMeta("kdf_time"); timeStr != "" {
		saltB64, _ := v.store.GetMeta("kdf_salt")
		salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
		if decodeErr != nil {
			return fmt.Errorf("decode kdf_salt: %w", decodeErr)
		}
		newKey, deriveErr := v.enc.DeriveKeyFromPassword(rawKey, salt, crypto.DefaultKDFParams())
		if deriveErr != nil {
			return fmt.Errorf("derive key: %w", deriveErr)
		}
		return v.store.ExecTx(func() error {
			for _, s := range all {
				plaintext, decryptErr := v.decrypt(s.EncryptedValue, s.IV)
				if decryptErr != nil {
					return fmt.Errorf("decrypt %s: %w", s.Name, decryptErr)
				}
				var ciphertext, iv []byte
				var encryptErr error
				if v.aad != nil {
					ciphertext, iv, encryptErr = v.enc.EncryptWithAAD(plaintext, newKey, v.aad)
				} else {
					ciphertext, iv, encryptErr = v.enc.Encrypt(plaintext, newKey)
				}
				for i := range plaintext {
					plaintext[i] = 0
				}
				if encryptErr != nil {
					return fmt.Errorf("encrypt %s: %w", s.Name, encryptErr)
				}
				if err = v.store.SetSecret(s.Name, ciphertext, iv, s.Tags); err != nil {
					return fmt.Errorf("update %s: %w", s.Name, err)
				}
			}
			if err = v.store.SetMeta("kdf_time", strconv.Itoa(int(crypto.DefaultKDFParams().Time))); err != nil {
				return err
			}
			if err = v.store.SetMeta("kdf_memory", strconv.Itoa(int(crypto.DefaultKDFParams().Memory))); err != nil {
				return err
			}
			if err = v.store.SetMeta("kdf_threads", strconv.Itoa(int(crypto.DefaultKDFParams().Threads))); err != nil {
				return err
			}
			v.key = newKey
			return nil
		})
	}

	saltB64, _ := v.store.GetMeta("kdf_salt")
	if saltB64 != "" {
		salt, decodeErr := base64.StdEncoding.DecodeString(saltB64)
		if decodeErr != nil {
			return fmt.Errorf("decode kdf_salt: %w", decodeErr)
		}
		newKey, err = v.enc.KeyToBufferV2WithSalt(rawKey, salt)
		if err != nil {
			return fmt.Errorf("derive key with salt: %w", err)
		}
	}

	return v.store.ExecTx(func() error {
		for _, s := range all {
			var plaintext []byte
			plaintext, err = v.decrypt(s.EncryptedValue, s.IV)
			if err != nil {
				return fmt.Errorf("decrypt %s: %w", s.Name, err)
			}
			var ciphertext, iv []byte
			ciphertext, iv, err = v.enc.Encrypt(plaintext, newKey)
			for i := range plaintext {
				plaintext[i] = 0
			}
			if err != nil {
				return fmt.Errorf("encrypt %s: %w", s.Name, err)
			}
			err = v.store.SetSecret(s.Name, ciphertext, iv, s.Tags)
			if err != nil {
				return fmt.Errorf("update %s: %w", s.Name, err)
			}
		}
		return v.store.SetMeta("kdf_version", strconv.Itoa(crypto.CurrentKDFVersion))
	})
}

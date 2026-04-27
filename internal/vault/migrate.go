package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/aatumaykin/psst/internal/crypto"
)

func (v *Vault) MigrateKDF(ctx context.Context) error {
	key, err := v.copyKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)

	all, err := v.store.GetAllSecrets(ctx)
	if err != nil {
		return fmt.Errorf("get secrets: %w", err)
	}

	v.mu.RLock()
	rawKey := v.rawKey
	v.mu.RUnlock()
	if rawKey == "" {
		return errors.New("vault not unlocked: no raw key available")
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
			plaintext, err = v.enc.Decrypt(s.EncryptedValue, s.IV, key)
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
	v.mu.Lock()
	crypto.ZeroBytes(v.key)
	v.key = newKey
	v.mu.Unlock()
	return nil
}

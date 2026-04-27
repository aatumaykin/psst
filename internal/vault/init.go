package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)

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
			return fmt.Errorf("no key available: set PSST_PASSWORD or ensure keychain is accessible: %w", err)
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

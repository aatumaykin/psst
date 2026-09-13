package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/kdf"
	"github.com/aatumaykin/psst/internal/store"
)

func (v *Vault) VerifyAllDecryptable(ctx context.Context) error {
	key, err := v.copyKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)

	all, err := v.store.GetAllSecrets(ctx)
	if err != nil {
		return fmt.Errorf("get secrets: %w", err)
	}
	for _, s := range all {
		plaintext, decErr := v.decryptSecret(s.EncryptedValue, s.IV, key, s.Name)
		if decErr != nil {
			return fmt.Errorf("secret %s is undecryptable under the current key", s.Name)
		}
		crypto.ZeroBytes(plaintext)
	}
	return nil
}

func (v *Vault) Rotate(ctx context.Context, newPassword string, params *kdf.Params) (int, error) {
	key, err := v.copyKey()
	if err != nil {
		return 0, err
	}
	defer crypto.ZeroBytes(key)

	gs, ok := v.store.(*store.GitStore)
	if !ok {
		return 0, errors.New("rotate requires git storage")
	}
	current := crypto.KDFParams{
		Time:    uint32(metaAtoi(ctx, v.store, "kdf_time")),
		Memory:  uint32(metaAtoi(ctx, v.store, "kdf_memory")),
		Threads: uint8(metaAtoi(ctx, v.store, "kdf_threads")),
	}
	target := current
	if params != nil {
		if params.Time < current.Time || params.Memory < current.Memory || params.Threads < current.Threads {
			return 0, errors.New("rotation must not weaken KDF parameters")
		}
		target = *params
	}
	salt := make([]byte, saltSize)
	if _, err = rand.Read(salt); err != nil {
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
			crypto.ZeroBytes(newKey)
		}
	}()
	err = gs.ExecTxMsg(ctx, "psst: rotate", func() error {
		all, err := v.store.GetAllSecrets(ctx)
		if err != nil {
			return fmt.Errorf("get secrets: %w", err)
		}
		for _, s := range all {
			plaintext, derr := v.decryptSecret(s.EncryptedValue, s.IV, key, s.Name)
			if derr != nil {
				return fmt.Errorf("secret %s is undecryptable under the current key", s.Name)
			}
			var ct, iv []byte
			ct, iv, derr = v.enc.EncryptWithAAD(plaintext, newKey, newAAD)
			crypto.ZeroBytes(plaintext)
			if derr != nil {
				return fmt.Errorf("encrypt %s: %w", s.Name, derr)
			}
			if err := v.store.SetSecret(ctx, s.Name, ct, iv, s.Tags); err != nil {
				return fmt.Errorf("update %s: %w", s.Name, err)
			}
			rotated++
		}
		if params != nil {
			if err := v.store.SetMeta(ctx, "kdf_time", strconv.Itoa(int(target.Time))); err != nil {
				return fmt.Errorf("set kdf_time: %w", err)
			}
			if err := v.store.SetMeta(ctx, "kdf_memory", strconv.Itoa(int(target.Memory))); err != nil {
				return fmt.Errorf("set kdf_memory: %w", err)
			}
			if err := v.store.SetMeta(ctx, "kdf_threads", strconv.Itoa(int(target.Threads))); err != nil {
				return fmt.Errorf("set kdf_threads: %w", err)
			}
		}
		return gs.RotateSalt(ctx, newSaltB64)
	})
	if err != nil {
		return rotated, err
	}
	success = true
	v.mu.Lock()
	crypto.ZeroBytes(v.key)
	v.key = newKey
	v.aad = newAAD
	v.mu.Unlock()
	gs.SetUnlockedFingerprint(gs.FingerprintOfCurrent())
	return rotated, nil
}

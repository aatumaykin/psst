package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
)

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

	all, verifyErr := v.store.GetAllSecrets(ctx)
	if verifyErr != nil {
		return fmt.Errorf("verify vault: %w", verifyErr)
	}

	verifyIV, ivErr := v.store.GetMeta(ctx, "verify_iv")
	verifyData, dataErr := v.store.GetMeta(ctx, "verify_data")

	verified := false
	if ivErr == nil && dataErr == nil && verifyIV != "" && verifyData != "" {
		ivBytes, ivDecodeErr := base64.StdEncoding.DecodeString(verifyIV)
		if ivDecodeErr != nil {
			return fmt.Errorf("decode verify_iv: %w", ivDecodeErr)
		}
		dataBytes, dataDecodeErr := base64.StdEncoding.DecodeString(verifyData)
		if dataDecodeErr != nil {
			return fmt.Errorf("decode verify_data: %w", dataDecodeErr)
		}
		if _, decErr := v.enc.Decrypt(dataBytes, ivBytes, key); decErr != nil {
			return v.failUnlock(ctx, key)
		}
		verified = true
	} else if len(all) > 0 {
		if _, decErr := v.enc.Decrypt(all[0].EncryptedValue, all[0].IV, key); decErr != nil {
			return v.failUnlock(ctx, key)
		}
		verified = true
	}

	v.mu.Lock()
	v.key = key
	v.mu.Unlock()

	if verified {
		_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
		_ = v.store.SetMeta(ctx, metaUnlockLockedUntil, "")
		_ = v.store.SetMeta(ctx, metaUnlockCycle, "0")
	}
	return nil
}

func (v *Vault) failUnlock(ctx context.Context, key []byte) error {
	crypto.ZeroBytes(key)
	attempts, _ := v.store.IncrementMetaInt(ctx, metaUnlockAttempts, 1)
	if attempts >= maxUnlockAttempts {
		cycle := 0
		if cycleStr, cycleErr := v.store.GetMeta(ctx, metaUnlockCycle); cycleErr == nil {
			if n, e := strconv.Atoi(cycleStr); e == nil {
				cycle = n
			}
		}

		lockDuration := min(
			time.Duration(unlockDelayBaseMs)*time.Millisecond*time.Duration(1<<uint(cycle)),
			maxLockDuration,
		)
		lockedUntil := time.Now().Add(lockDuration)
		_ = v.store.SetMeta(ctx, metaUnlockLockedUntil, lockedUntil.Format(time.RFC3339))
		_ = v.store.SetMeta(ctx, metaUnlockAttempts, "0")
		_ = v.store.SetMeta(ctx, metaUnlockCycle, strconv.Itoa(cycle+1))
	}
	return errors.New("authentication failed")
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

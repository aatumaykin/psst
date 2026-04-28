package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
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
	v.mu.Lock()
	v.rawKey = rawKey
	v.mu.Unlock()

	kdfVersion, err := v.readKDFVersion(ctx)
	if err != nil {
		return err
	}
	var key []byte
	switch kdfVersion {
	case 1:
		v.mu.Lock()
		v.v1KDF = true
		v.mu.Unlock()
		key, err = v.enc.KeyToBuffer(string(rawKey))
		defer func() {
			if err == nil {
				fmt.Fprintln(os.Stderr,
					"Warning: vault uses legacy KDF (SHA-256). Run 'psst migrate' to upgrade to Argon2id.")
			}
		}()
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
		key, err = v.enc.KeyToBufferV2WithSalt(string(rawKey), salt)
	default:
		return fmt.Errorf("unsupported KDF version: %d", kdfVersion)
	}
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	verified, hasData := v.tryVerify(ctx, key)

	if !verified && hasData && kdfVersion == crypto.KDFVersion2 {
		crypto.ZeroBytes(key)
		legacyKey, legacyErr := v.tryLegacyV2Key(rawKey)
		if legacyErr == nil && legacyKey != nil {
			legacyVerified, _ := v.tryVerify(ctx, legacyKey)
			if legacyVerified {
				key = legacyKey
				verified = true
				v.mu.Lock()
				v.legacyV2 = true
				v.mu.Unlock()
				fmt.Fprintln(os.Stderr,
					"Warning: vault uses legacy encryption (pre-v1.3.0). Run 'psst migrate' to upgrade.")
			} else {
				crypto.ZeroBytes(legacyKey)
			}
		}
	}

	if !verified {
		crypto.ZeroBytes(key)
		if !hasData {
			return errors.New("vault integrity check failed: no verification data. Re-initialize with 'psst init'")
		}
		return v.failUnlock(ctx, nil)
	}

	v.mu.Lock()
	v.key = key
	if !v.hasVerifyData(ctx) {
		v.legacyV2 = true
	}
	v.mu.Unlock()

	for k, val := range map[string]string{
		metaUnlockAttempts:    "0",
		metaUnlockLockedUntil: "",
		metaUnlockCycle:       "0",
	} {
		if metaErr := v.store.SetMeta(ctx, k, val); metaErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to reset %s: %v\n", k, metaErr)
		}
	}
	return nil
}

func (v *Vault) hasVerifyData(ctx context.Context) bool {
	verifyIV, _ := v.store.GetMeta(ctx, "verify_iv")
	verifyData, _ := v.store.GetMeta(ctx, "verify_data")
	return verifyIV != "" && verifyData != ""
}

func (v *Vault) tryVerify(ctx context.Context, key []byte) (verified bool, hasData bool) {
	verifyIV, ivErr := v.store.GetMeta(ctx, "verify_iv")
	verifyData, dataErr := v.store.GetMeta(ctx, "verify_data")

	if ivErr == nil && dataErr == nil && verifyIV != "" && verifyData != "" {
		ivBytes, ivDecodeErr := base64.StdEncoding.DecodeString(verifyIV)
		if ivDecodeErr != nil {
			return false, true
		}
		dataBytes, dataDecodeErr := base64.StdEncoding.DecodeString(verifyData)
		if dataDecodeErr != nil {
			return false, true
		}
		_, decErr := v.enc.Decrypt(dataBytes, ivBytes, key)
		return decErr == nil, true
	}

	all, verifyErr := v.store.GetAllSecrets(ctx)
	if verifyErr != nil {
		return false, false
	}
	if len(all) > 0 {
		_, decErr := v.enc.Decrypt(all[0].EncryptedValue, all[0].IV, key)
		return decErr == nil, true
	}
	return false, false
}

func (v *Vault) tryLegacyV2Key(rawKey []byte) ([]byte, error) {
	decoded, decodeErr := base64.StdEncoding.DecodeString(string(rawKey))
	if decodeErr != nil || len(decoded) != 32 {
		return nil, errors.New("not a legacy base64-encoded 32-byte key")
	}
	key := make([]byte, 32)
	copy(key, decoded)
	return key, nil
}

func (v *Vault) failUnlock(ctx context.Context, key []byte) error {
	if key != nil {
		crypto.ZeroBytes(key)
	}
	attempts, incErr := v.store.IncrementMetaInt(ctx, metaUnlockAttempts, 1)
	if incErr != nil {
		return fmt.Errorf("authentication failed (rate-limit write error: %w)", incErr)
	}
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
		if metaErr := v.store.SetMeta(ctx, metaUnlockLockedUntil, lockedUntil.Format(time.RFC3339)); metaErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to persist lock state: %v\n", metaErr)
		}
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

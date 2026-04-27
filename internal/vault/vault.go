package vault

import (
	"errors"
	"sync"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)

type Vault struct {
	mu    sync.RWMutex
	enc   crypto.Encryptor
	kp    keyring.KeyProvider
	store store.SecretStore
	key   []byte
}

const (
	serviceName   = "psst"
	accountName   = "vault-key"
	maxHistory    = 10
	saltSize      = 16

	maxUnlockAttempts     = 10
	unlockDelayBaseMs     = 500
	maxLockDuration       = 5 * time.Minute
	metaUnlockAttempts    = "unlock_attempts"
	metaUnlockLockedUntil = "unlock_locked_until"
	metaUnlockCycle       = "unlock_cycle"
)

func New(enc crypto.Encryptor, kp keyring.KeyProvider, s store.SecretStore) *Vault {
	return &Vault{enc: enc, kp: kp, store: s}
}

func (v *Vault) Close() error {
	v.mu.Lock()
	crypto.ZeroBytes(v.key)
	v.key = nil
	v.mu.Unlock()
	return v.store.Close()
}

func (v *Vault) requireUnlock() error {
	v.mu.RLock()
	unlocked := v.key != nil
	v.mu.RUnlock()
	if !unlocked {
		return errors.New("vault is locked: unlock required")
	}
	return nil
}

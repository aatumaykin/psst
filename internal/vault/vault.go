package vault

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/store"
)

type Vault struct {
	mu       sync.RWMutex
	enc      crypto.Encryptor
	kp       keyring.KeyProvider
	store    store.SecretStore
	key      []byte
	rawKey   []byte
	v1KDF    bool
	legacyV2 bool
}

const (
	serviceName = "psst"
	accountName = "vault-key"
	maxHistory  = 10
	saltSize    = 16

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

func Open(vaultPath string) (*Vault, error) {
	enc := crypto.NewAESGCM()
	kp := keyring.NewProvider(enc)

	s, err := store.NewSQLite(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	if err = s.InitSchema(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return New(enc, kp, s), nil
}

func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	crypto.ZeroBytes(v.key)
	v.key = nil
	crypto.ZeroBytes(v.rawKey)
	v.rawKey = nil
	return v.store.Close()
}

func (v *Vault) withRLock(fn func() error) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.key == nil {
		return errors.New("vault is locked: unlock required")
	}
	return fn()
}

func (v *Vault) checkKDFBlocking() error {
	if v.v1KDF {
		fmt.Fprintln(os.Stderr, "Warning: vault uses legacy KDF (V1). Run 'psst migrate' to upgrade.")
	}
	return nil
}

func (v *Vault) copyKey() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.checkKDFBlocking(); err != nil {
		return nil, err
	}
	if v.key == nil {
		return nil, errors.New("vault is locked")
	}
	key := make([]byte, len(v.key))
	copy(key, v.key)
	return key, nil
}

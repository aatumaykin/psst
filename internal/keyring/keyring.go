package keyring

import (
	"os"
)

// KeyDeriver derives encryption keys from passwords.
type KeyDeriver interface {
	KeyToBuffer(key string) ([]byte, error)
	GenerateKey() ([]byte, error)
}

// KeyProvider retrieves and stores encryption keys using the OS keychain or env vars.
type KeyProvider interface {
	GetRawKey(service, account string) ([]byte, error)
	SetKey(service, account string, key []byte) error
	IsAvailable() bool
	GenerateKey() ([]byte, error)
}

// NewProvider returns an OS keychain provider if available, otherwise an env-based one.
func NewProvider(deriver KeyDeriver) KeyProvider {
	oskr := &OSKeyring{deriver: deriver}
	if oskr.IsAvailable() {
		return oskr
	}
	return &EnvVarProvider{deriver: deriver}
}

func IsKeychainAvailable() bool {
	return (&OSKeyring{}).IsAvailable()
}

func IsEnvPasswordSet() bool {
	return os.Getenv("PSST_PASSWORD") != ""
}

func IsEnvProvider(kp KeyProvider) bool {
	_, ok := kp.(*EnvVarProvider)
	return ok
}

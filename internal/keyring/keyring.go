package keyring

import (
	"os"
)

type KeyDeriver interface {
	KeyToBuffer(key string) ([]byte, error)
	KeyToBufferV2(key string) ([]byte, error)
	GenerateKey() ([]byte, error)
}

type KeyProvider interface {
	GetRawKey(service, account string) (string, error)
	SetKey(service, account string, key []byte) error
	IsAvailable() bool
	GenerateKey() ([]byte, error)
}

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

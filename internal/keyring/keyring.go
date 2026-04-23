package keyring

import "github.com/user/psst/internal/crypto"

type KeyProvider interface {
	GetKey(service, account string) ([]byte, error)
	SetKey(service, account string, key []byte) error
	IsAvailable() bool
	GenerateKey() ([]byte, error)
}

func NewProvider(enc *crypto.AESGCM) KeyProvider {
	os := &OSKeyring{enc: enc}
	if os.IsAvailable() {
		return os
	}
	return &EnvVarProvider{enc: enc}
}

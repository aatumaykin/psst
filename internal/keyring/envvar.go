package keyring

import (
	"fmt"
	"os"

	"github.com/user/psst/internal/crypto"
)

type EnvVarProvider struct {
	enc *crypto.AESGCM
}

func (e *EnvVarProvider) GetKey(service, account string) ([]byte, error) {
	password := os.Getenv("PSST_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("PSST_PASSWORD not set and OS keychain unavailable")
	}
	return e.enc.KeyToBuffer(password)
}

func (e *EnvVarProvider) SetKey(service, account string, key []byte) error {
	return nil
}

func (e *EnvVarProvider) IsAvailable() bool {
	return os.Getenv("PSST_PASSWORD") != ""
}

func (e *EnvVarProvider) GenerateKey() ([]byte, error) {
	return e.enc.GenerateKey()
}

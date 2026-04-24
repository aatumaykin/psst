package keyring

import (
	"fmt"
	"os"
)

type EnvVarProvider struct {
	deriver KeyDeriver
}

func (e *EnvVarProvider) GetKey(service, account string) ([]byte, error) {
	password := os.Getenv("PSST_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("PSST_PASSWORD not set and OS keychain unavailable")
	}
	return e.deriver.KeyToBuffer(password)
}

func (e *EnvVarProvider) GetRawKey(service, account string) (string, error) {
	password := os.Getenv("PSST_PASSWORD")
	if password == "" {
		return "", fmt.Errorf("PSST_PASSWORD not set and OS keychain unavailable")
	}
	return password, nil
}

func (e *EnvVarProvider) SetKey(service, account string, key []byte) error {
	return nil
}

func (e *EnvVarProvider) IsAvailable() bool {
	return os.Getenv("PSST_PASSWORD") != ""
}

func (e *EnvVarProvider) GenerateKey() ([]byte, error) {
	return e.deriver.GenerateKey()
}

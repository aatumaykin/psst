package keyring

import (
	"errors"
	"os"
)

type EnvVarProvider struct {
	deriver KeyDeriver
}

func (e *EnvVarProvider) GetKey(_, _ string) ([]byte, error) {
	password := os.Getenv("PSST_PASSWORD")
	if password == "" {
		return nil, errors.New("PSST_PASSWORD not set and OS keychain unavailable")
	}
	return e.deriver.KeyToBuffer(password)
}

func (e *EnvVarProvider) GetRawKey(_, _ string) (string, error) {
	password := os.Getenv("PSST_PASSWORD")
	if password == "" {
		return "", errors.New("PSST_PASSWORD not set and OS keychain unavailable")
	}
	return password, nil
}

func (e *EnvVarProvider) SetKey(_, _ string, _ []byte) error {
	return nil
}

func (e *EnvVarProvider) IsAvailable() bool {
	return os.Getenv("PSST_PASSWORD") != ""
}

func (e *EnvVarProvider) GenerateKey() ([]byte, error) {
	return e.deriver.GenerateKey()
}

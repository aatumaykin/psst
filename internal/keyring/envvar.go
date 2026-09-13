package keyring

import (
	"errors"
	"os"
)

type EnvVarProvider struct {
	deriver KeyDeriver
}

func (e *EnvVarProvider) GetRawKey(_, _ string) ([]byte, error) {
	password := os.Getenv("PSST_PASSWORD")
	if password == "" {
		return nil, errors.New("PSST_PASSWORD not set and OS keychain unavailable")
	}
	os.Unsetenv("PSST_PASSWORD")
	return []byte(password), nil
}

func (e *EnvVarProvider) SetKey(_, _ string, _ []byte) error {
	return errors.New("cannot store key: PSST_PASSWORD mode does not support key storage")
}

func (e *EnvVarProvider) IsAvailable() bool {
	return os.Getenv("PSST_PASSWORD") != ""
}

func (e *EnvVarProvider) GenerateKey() ([]byte, error) {
	if e.deriver == nil {
		return nil, errors.New("no key deriver available")
	}
	return e.deriver.GenerateKey()
}

package keyring

import (
	"encoding/base64"
	"errors"
	"fmt"

	keyring "github.com/zalando/go-keyring"
)

type OSKeyring struct {
	deriver KeyDeriver
}

func (o *OSKeyring) GetRawKey(service, account string) (string, error) {
	encoded, err := keyring.Get(service, account)
	if err != nil {
		return "", fmt.Errorf("get from keychain: %w", err)
	}
	return encoded, nil
}

func (o *OSKeyring) SetKey(service, account string, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return keyring.Set(service, account, encoded)
}

func (o *OSKeyring) IsAvailable() bool {
	const testSvc = "psst-avail-check"
	const testAcc = "test"
	const testVal = "psst-availability-probe"
	if err := keyring.Set(testSvc, testAcc, testVal); err != nil {
		return false
	}
	got, err := keyring.Get(testSvc, testAcc)
	_ = keyring.Delete(testSvc, testAcc)
	return err == nil && got == testVal
}

func (o *OSKeyring) GenerateKey() ([]byte, error) {
	if o.deriver != nil {
		return o.deriver.GenerateKey()
	}
	return nil, errors.New("no key deriver available")
}

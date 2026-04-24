package keyring

import (
	"encoding/base64"
	"fmt"

	"github.com/aatumaykin/psst/internal/crypto"
	keyring "github.com/zalando/go-keyring"
)

type OSKeyring struct {
	enc *crypto.AESGCM
}

func (o *OSKeyring) GetKey(service, account string) ([]byte, error) {
	encoded, err := keyring.Get(service, account)
	if err != nil {
		return nil, fmt.Errorf("get from keychain: %w", err)
	}
	return o.enc.KeyToBuffer(encoded)
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
	keyring.Delete(testSvc, testAcc)
	return err == nil && got == testVal
}

func (o *OSKeyring) GenerateKey() ([]byte, error) {
	return o.enc.GenerateKey()
}

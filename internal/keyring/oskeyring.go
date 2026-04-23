package keyring

import (
	"encoding/base64"
	"fmt"

	"github.com/user/psst/internal/crypto"
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

func (o *OSKeyring) SetKey(service, account string, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return keyring.Set(service, account, encoded)
}

func (o *OSKeyring) IsAvailable() bool {
	err := keyring.Set("psst-test", "availability-check", "test")
	if err != nil {
		return false
	}
	keyring.Delete("psst-test", "availability-check")
	return true
}

func (o *OSKeyring) GenerateKey() ([]byte, error) {
	return o.enc.GenerateKey()
}

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

type AESGCM struct{}

func NewAESGCM() *AESGCM {
	return &AESGCM{}
}

func (a *AESGCM) Encrypt(plaintext []byte, key []byte) (ciphertext, iv []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create GCM: %w", err)
	}

	iv = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("generate IV: %w", err)
	}

	ciphertext = gcm.Seal(nil, iv, plaintext, nil)
	return ciphertext, iv, nil
}

func (a *AESGCM) Decrypt(ciphertext []byte, iv []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

func (a *AESGCM) KeyToBuffer(key string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	hash := sha256.Sum256([]byte(key))
	return hash[:], nil
}

func (a *AESGCM) KeyToBufferV2(key string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	salt := sha256.Sum256([]byte("psst-argon2id-v2-salt"))
	return argon2.IDKey([]byte(key), salt[:], 3, 64*1024, 4, 32), nil
}

func (a *AESGCM) GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

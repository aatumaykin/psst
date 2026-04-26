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

const (
	aesKeySize       = 32
	argon2Iterations = 3
	argon2Memory     = 64 * 1024
	argon2Threads    = 4
)

type AESGCM struct{}

func NewAESGCM() *AESGCM {
	return &AESGCM{}
}

func (a *AESGCM) Encrypt(plaintext []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create GCM: %w", err)
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("generate IV: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
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
	if err == nil && len(decoded) == aesKeySize {
		return decoded, nil
	}

	hash := sha256.Sum256([]byte(key))
	return hash[:], nil
}

func (a *AESGCM) KeyToBufferV2(key string) ([]byte, error) {
	salt := sha256.Sum256([]byte("psst-argon2id-v2-salt"))
	return argon2.IDKey([]byte(key), salt[:], argon2Iterations, argon2Memory, argon2Threads, aesKeySize), nil
}

func (a *AESGCM) KeyToBufferV2WithSalt(key string, salt []byte) ([]byte, error) {
	return argon2.IDKey([]byte(key), salt, argon2Iterations, argon2Memory, argon2Threads, aesKeySize), nil
}

func (a *AESGCM) GenerateKey() ([]byte, error) {
	key := make([]byte, aesKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

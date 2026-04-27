package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	aesKeySize       = 32
	saltSize         = 16
	argon2Iterations = 3
	argon2Memory     = 64 * 1024
	argon2Threads    = 4
)

// AESGCM implements Encryptor using AES-256-GCM.
type AESGCM struct{}

// NewAESGCM creates a new AESGCM encryptor.
func NewAESGCM() *AESGCM {
	return &AESGCM{}
}

// Encrypt encrypts plaintext using AES-256-GCM.
func (a *AESGCM) Encrypt(plaintext []byte, key []byte) ([]byte, []byte, error) {
	if len(key) != aesKeySize {
		return nil, nil, fmt.Errorf("invalid key size: %d bytes, expected %d", len(key), aesKeySize)
	}

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

// Decrypt decrypts AES-256-GCM ciphertext using the given IV and key.
func (a *AESGCM) Decrypt(ciphertext []byte, iv []byte, key []byte) ([]byte, error) {
	if len(key) != aesKeySize {
		return nil, fmt.Errorf("invalid key size: %d bytes, expected %d", len(key), aesKeySize)
	}

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

// KeyToBuffer derives a 32-byte key from a password via SHA-256 or base64 decode.
func (a *AESGCM) KeyToBuffer(key string) ([]byte, error) {
	if key == "" {
		return nil, errors.New("empty key/password not allowed")
	}

	decoded, err := base64.StdEncoding.DecodeString(key)
	if err == nil && len(decoded) == aesKeySize {
		// Base64 path: used when reading a pre-derived key stored in the OS keychain.
		// The keychain stores the full 32-byte key encoded as base64.
		return decoded, nil
	}

	hash := sha256.Sum256([]byte(key))
	return hash[:], nil
}

// Deprecated: KeyToBufferV2 uses a hardcoded salt. Use KeyToBufferV2WithSalt instead.
func (a *AESGCM) KeyToBufferV2(key string) ([]byte, error) {
	salt := sha256.Sum256([]byte("psst-argon2id-v2-salt"))
	return argon2.IDKey([]byte(key), salt[:], argon2Iterations, argon2Memory, argon2Threads, aesKeySize), nil
}

// KeyToBufferV2WithSalt derives a 32-byte key using Argon2id with the provided salt.
func (a *AESGCM) KeyToBufferV2WithSalt(key string, salt []byte) ([]byte, error) {
	if len(salt) != saltSize {
		return nil, fmt.Errorf("invalid salt size: %d, expected %d", len(salt), saltSize)
	}
	return argon2.IDKey([]byte(key), salt, argon2Iterations, argon2Memory, argon2Threads, aesKeySize), nil
}

// ZeroBytes overwrites the slice contents with zeroes.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateKey creates a cryptographically random 32-byte key.
func (a *AESGCM) GenerateKey() ([]byte, error) {
	key := make([]byte, aesKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

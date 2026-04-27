package crypto

// Encryptor provides symmetric encryption and key derivation operations.
type Encryptor interface {
	// Encrypt encrypts plaintext with the given key, returning ciphertext and IV.
	Encrypt(plaintext []byte, key []byte) (ciphertext, iv []byte, err error)
	// Decrypt decrypts ciphertext using the given IV and key.
	Decrypt(ciphertext, iv []byte, key []byte) ([]byte, error)
	// KeyToBuffer derives a 32-byte key from a password string (V1: SHA-256 or base64 decode).
	KeyToBuffer(key string) ([]byte, error)
	// KeyToBufferV2 derives a 32-byte key using Argon2id with a hardcoded salt.
	KeyToBufferV2(key string) ([]byte, error)
	// KeyToBufferV2WithSalt derives a 32-byte key using Argon2id with the provided salt.
	KeyToBufferV2WithSalt(key string, salt []byte) ([]byte, error)
	// GenerateKey creates a cryptographically random 32-byte key.
	GenerateKey() ([]byte, error)
}

package crypto

// Encryptor provides symmetric encryption and key derivation operations.
type Encryptor interface {
	Encrypt(plaintext []byte, key []byte, aad ...[]byte) (ciphertext, iv []byte, err error)
	Decrypt(ciphertext, iv []byte, key []byte, aad ...[]byte) ([]byte, error)
	KeyToBuffer(key string) ([]byte, error)
	KeyToBufferV2WithSalt(key string, salt []byte) ([]byte, error)
	GenerateKey() ([]byte, error)
}

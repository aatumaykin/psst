package crypto

type Encryptor interface {
	Encrypt(plaintext []byte, key []byte, aad ...[]byte) (ciphertext, iv []byte, err error)
	Decrypt(ciphertext, iv []byte, key []byte, aad ...[]byte) ([]byte, error)
	EncryptWithAAD(plaintext, key, aad []byte) (ciphertext, iv []byte, err error)
	DecryptWithAAD(ciphertext, iv, key, aad []byte) ([]byte, error)
	DeriveKeyFromPassword(password string, salt []byte, params KDFParams) ([]byte, error)
	KeyToBuffer(key string) ([]byte, error)
	KeyToBufferV2WithSalt(key string, salt []byte) ([]byte, error)
	GenerateKey() ([]byte, error)
}

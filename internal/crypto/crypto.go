package crypto

type Encryptor interface {
	Encrypt(plaintext []byte, key []byte) (ciphertext, iv []byte, err error)
	Decrypt(ciphertext, iv []byte, key []byte) ([]byte, error)
	KeyToBuffer(key string) ([]byte, error)
	GenerateKey() ([]byte, error)
}

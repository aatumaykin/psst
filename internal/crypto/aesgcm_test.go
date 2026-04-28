package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc := NewAESGCM()
	key := make([]byte, 32)

	plaintext := []byte("hello secret world")
	ciphertext, iv, err := enc.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(iv) != 12 {
		t.Fatalf("IV length = %d, want 12", len(iv))
	}

	decrypted, err := enc.Decrypt(ciphertext, iv, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptProducesDifferentCiphertext(t *testing.T) {
	enc := NewAESGCM()
	key := make([]byte, 32)
	plaintext := []byte("same data")

	ct1, iv1, _ := enc.Encrypt(plaintext, key)
	ct2, iv2, _ := enc.Encrypt(plaintext, key)

	if string(ct1) == string(ct2) {
		t.Fatal("two encryptions of same data should produce different ciphertext")
	}
	if string(iv1) == string(iv2) {
		t.Fatal("two encryptions should use different IVs")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	enc := NewAESGCM()
	key := make([]byte, 32)
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1

	plaintext := []byte("secret")
	ct, iv, _ := enc.Encrypt(plaintext, key)

	_, err := enc.Decrypt(ct, iv, wrongKey)
	if err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestKeyToBuffer_Base64(t *testing.T) {
	enc := NewAESGCM()
	raw := make([]byte, 32)
	raw[0] = 42
	b64 := base64.StdEncoding.EncodeToString(raw)

	result, err := enc.KeyToBuffer(b64)
	if err != nil {
		t.Fatalf("KeyToBuffer failed: %v", err)
	}
	if result[0] != 42 {
		t.Fatalf("first byte = %d, want 42", result[0])
	}
}

func TestKeyToBuffer_Password(t *testing.T) {
	enc := NewAESGCM()
	key, err := enc.KeyToBuffer("mypassword")
	if err != nil {
		t.Fatalf("KeyToBuffer failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestGenerateKey(t *testing.T) {
	enc := NewAESGCM()
	key, err := enc.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}

	key2, _ := enc.GenerateKey()
	if string(key) == string(key2) {
		t.Fatal("two generated keys should be different")
	}
}

func TestKeyToBufferV2_Argon2id(t *testing.T) {
	enc := NewAESGCM()
	key1, err := enc.KeyToBufferV2("mypassword")
	if err != nil {
		t.Fatalf("KeyToBufferV2 failed: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("key length = %d, want 32", len(key1))
	}

	key2, _ := enc.KeyToBufferV2("mypassword")
	if string(key1) != string(key2) {
		t.Fatal("same password should produce same key with Argon2id")
	}

	key3, _ := enc.KeyToBufferV2("otherpassword")
	if string(key1) == string(key3) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestKeyToBufferV2_NeverBypassesArgon2id(t *testing.T) {
	enc := NewAESGCM()
	raw := make([]byte, 32)
	raw[0] = 42
	b64 := base64.StdEncoding.EncodeToString(raw)

	result, err := enc.KeyToBufferV2(b64)
	if err != nil {
		t.Fatalf("KeyToBufferV2 failed: %v", err)
	}

	if string(result) == string(raw) {
		t.Fatal("KeyToBufferV2 must not return raw base64-decoded bytes; Argon2id KDF must always be applied")
	}

	if len(result) != 32 {
		t.Fatalf("key length = %d, want 32", len(result))
	}

	salt := sha256.Sum256([]byte("psst-argon2id-v2-salt"))
	expected := argon2.IDKey([]byte(b64), salt[:], argon2Iterations, argon2Memory, argon2Threads, aesKeySize)
	if string(result) != string(expected) {
		t.Fatal("KeyToBufferV2 should use Argon2id on the password string, not raw decoded bytes")
	}
}

func TestZeroBytes(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5}
	ZeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte at index %d = %d, want 0", i, b)
		}
	}
}

func TestZeroBytes_Empty(t *testing.T) {
	buf := []byte{}
	ZeroBytes(buf)
	if len(buf) != 0 {
		t.Fatal("empty slice should remain empty")
	}
}

func TestKeyToBuffer_EmptyPassword(t *testing.T) {
	enc := NewAESGCM()
	_, err := enc.KeyToBuffer("")
	if err == nil {
		t.Fatal("KeyToBuffer should reject empty password")
	}
}

func TestKeyToBufferV1_V2_ProduceDifferentKeys(t *testing.T) {
	enc := NewAESGCM()
	v1, _ := enc.KeyToBuffer("mypassword")
	v2, _ := enc.KeyToBufferV2("mypassword")
	if string(v1) == string(v2) {
		t.Fatal("v1 and v2 KDF should produce different keys from same password")
	}
}

func TestKeyToBufferV2WithSalt_Deterministic(t *testing.T) {
	enc := NewAESGCM()
	salt := make([]byte, saltSize)
	salt[0] = 1
	key1, err := enc.KeyToBufferV2WithSalt("mypassword", salt)
	if err != nil {
		t.Fatalf("KeyToBufferV2WithSalt failed: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("key length = %d, want 32", len(key1))
	}

	key2, _ := enc.KeyToBufferV2WithSalt("mypassword", salt)
	if string(key1) != string(key2) {
		t.Fatal("same password and salt should produce same key")
	}
}

func TestKeyToBufferV2WithSalt_DifferentSalts(t *testing.T) {
	enc := NewAESGCM()
	saltA := make([]byte, saltSize)
	saltA[0] = 1
	saltB := make([]byte, saltSize)
	saltB[0] = 2
	key1, _ := enc.KeyToBufferV2WithSalt("mypassword", saltA)
	key2, _ := enc.KeyToBufferV2WithSalt("mypassword", saltB)
	if string(key1) == string(key2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestKeyToBufferV2WithSalt_DifferentFromHardcoded(t *testing.T) {
	enc := NewAESGCM()
	v2, _ := enc.KeyToBufferV2("mypassword")
	salt := make([]byte, saltSize)
	salt[0] = 99
	withSalt, _ := enc.KeyToBufferV2WithSalt("mypassword", salt)
	if string(v2) == string(withSalt) {
		t.Fatal("custom salt should produce different key from hardcoded salt")
	}
}

func TestKeyToBufferV2WithSalt_NeverBypassesArgon2id(t *testing.T) {
	enc := NewAESGCM()
	raw := make([]byte, 32)
	raw[0] = 99
	b64 := base64.StdEncoding.EncodeToString(raw)
	salt := make([]byte, saltSize)
	salt[0] = 1

	result, err := enc.KeyToBufferV2WithSalt(b64, salt)
	if err != nil {
		t.Fatalf("KeyToBufferV2WithSalt failed: %v", err)
	}

	if string(result) == string(raw) {
		t.Fatal("KeyToBufferV2WithSalt must not return raw base64-decoded bytes; Argon2id KDF must always be applied")
	}

	expected := argon2.IDKey([]byte(b64), salt, argon2Iterations, argon2Memory, argon2Threads, aesKeySize)
	if string(result) != string(expected) {
		t.Fatal("KeyToBufferV2WithSalt should use Argon2id on the password string, not raw decoded bytes")
	}
}

func TestKeyToBufferV2WithSalt_RejectsWrongSaltSize(t *testing.T) {
	enc := NewAESGCM()
	_, err := enc.KeyToBufferV2WithSalt("mypassword", []byte("short"))
	if err == nil {
		t.Fatal("KeyToBufferV2WithSalt should reject undersized salt")
	}

	longSalt := make([]byte, saltSize+1)
	_, err = enc.KeyToBufferV2WithSalt("mypassword", longSalt)
	if err == nil {
		t.Fatal("KeyToBufferV2WithSalt should reject oversized salt")
	}

	emptySalt := []byte{}
	_, err = enc.KeyToBufferV2WithSalt("mypassword", emptySalt)
	if err == nil {
		t.Fatal("KeyToBufferV2WithSalt should reject empty salt")
	}
}

func TestEncrypt_RejectsWrongKeySize(t *testing.T) {
	enc := NewAESGCM()
	plaintext := []byte("test data")

	_, _, err := enc.Encrypt(plaintext, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("Encrypt should reject undersized key")
	}

	longKey := make([]byte, 64)
	_, _, err = enc.Encrypt(plaintext, longKey)
	if err == nil {
		t.Fatal("Encrypt should reject oversized key")
	}

	_, _, err = enc.Encrypt(plaintext, nil)
	if err == nil {
		t.Fatal("Encrypt should reject nil key")
	}
}

func TestAESGCM_EncryptDecryptWithAAD(t *testing.T) {
	enc := NewAESGCM()
	key := make([]byte, 32)
	plaintext := []byte("hello secret world")
	aad := []byte("my-secret-name")

	ciphertext, iv, err := enc.Encrypt(plaintext, key, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext, iv, key, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAESGCM_WrongAAD_FailsDecrypt(t *testing.T) {
	enc := NewAESGCM()
	key := make([]byte, 32)
	plaintext := []byte("hello secret world")
	aad := []byte("secret-a")

	ciphertext, iv, _ := enc.Encrypt(plaintext, key, aad)

	_, err := enc.Decrypt(ciphertext, iv, key, []byte("secret-b"))
	if err == nil {
		t.Fatal("decrypt with wrong AAD should fail")
	}
}

func TestAESGCM_NoAADStillWorks(t *testing.T) {
	enc := NewAESGCM()
	key := make([]byte, 32)
	plaintext := []byte("hello secret world")

	ciphertext, iv, err := enc.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext, iv, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAESGCM_EncryptWithAADDecryptWithout_Fails(t *testing.T) {
	enc := NewAESGCM()
	key := make([]byte, 32)
	plaintext := []byte("hello secret world")
	aad := []byte("secret-name")

	ciphertext, iv, _ := enc.Encrypt(plaintext, key, aad)

	_, err := enc.Decrypt(ciphertext, iv, key)
	if err == nil {
		t.Fatal("decrypt without AAD when encrypted with AAD should fail")
	}
}

func TestDecrypt_RejectsWrongKeySize(t *testing.T) {
	enc := NewAESGCM()

	_, err := enc.Decrypt([]byte("ciphertext"), []byte("iv"), []byte{1, 2, 3})
	if err == nil {
		t.Fatal("Decrypt should reject undersized key")
	}

	longKey := make([]byte, 64)
	_, err = enc.Decrypt([]byte("ciphertext"), []byte("iv"), longKey)
	if err == nil {
		t.Fatal("Decrypt should reject oversized key")
	}

	_, err = enc.Decrypt([]byte("ciphertext"), []byte("iv"), nil)
	if err == nil {
		t.Fatal("Decrypt should reject nil key")
	}
}

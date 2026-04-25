package crypto

import (
	"encoding/base64"
	"testing"
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

func TestKeyToBufferV2_Base64Passthrough(t *testing.T) {
	enc := NewAESGCM()
	raw := make([]byte, 32)
	raw[0] = 42
	b64 := base64.StdEncoding.EncodeToString(raw)

	result, err := enc.KeyToBufferV2(b64)
	if err != nil {
		t.Fatalf("KeyToBufferV2 failed: %v", err)
	}
	if result[0] != 42 {
		t.Fatalf("first byte = %d, want 42", result[0])
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
	salt := []byte("unique-vault-salt")
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
	key1, _ := enc.KeyToBufferV2WithSalt("mypassword", []byte("salt-a"))
	key2, _ := enc.KeyToBufferV2WithSalt("mypassword", []byte("salt-b"))
	if string(key1) == string(key2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestKeyToBufferV2WithSalt_DifferentFromHardcoded(t *testing.T) {
	enc := NewAESGCM()
	v2, _ := enc.KeyToBufferV2("mypassword")
	withSalt, _ := enc.KeyToBufferV2WithSalt("mypassword", []byte("custom-salt"))
	if string(v2) == string(withSalt) {
		t.Fatal("custom salt should produce different key from hardcoded salt")
	}
}

func TestKeyToBufferV2WithSalt_Base64Passthrough(t *testing.T) {
	enc := NewAESGCM()
	raw := make([]byte, 32)
	raw[0] = 99
	b64 := base64.StdEncoding.EncodeToString(raw)

	result, err := enc.KeyToBufferV2WithSalt(b64, []byte("any-salt"))
	if err != nil {
		t.Fatalf("KeyToBufferV2WithSalt failed: %v", err)
	}
	if result[0] != 99 {
		t.Fatalf("first byte = %d, want 99", result[0])
	}
}

package store

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/kdf"
)

func validMetaYAML() string {
	return "version: 1\n" +
		"kdf_algo: argon2id\n" +
		"kdf_time: 3\n" +
		"kdf_memory: 65536\n" +
		"kdf_threads: 4\n" +
		"salt: MDEyMzQ1Njc4OWFiY2RlZg==\n" +
		"cipher: aes-256-gcm\n"
}

func TestParseVaultMetaRoundTrip(t *testing.T) {
	m, err := ParseVaultMeta([]byte(validMetaYAML()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Params != kdf.Default() {
		t.Fatalf("params = %+v", m.Params)
	}
	again, err := ParseVaultMeta(m.Encode())
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if again.Fingerprint() != m.Fingerprint() {
		t.Fatal("fingerprint unstable")
	}
}

func TestParseVaultMetaRejects(t *testing.T) {
	cases := map[string]string{
		"bad version":  strings.Replace(validMetaYAML(), "version: 1", "version: 2", 1),
		"bad cipher":   strings.Replace(validMetaYAML(), "aes-256-gcm", "aes-128", 1),
		"bad algo":     strings.Replace(validMetaYAML(), "argon2id", "scrypt", 1),
		"weak memory":  strings.Replace(validMetaYAML(), "kdf_memory: 65536", "kdf_memory: 1024", 1),
		"weak time":    strings.Replace(validMetaYAML(), "kdf_time: 3", "kdf_time: 1", 1),
		"short salt":   strings.Replace(validMetaYAML(), "MDEyMzQ1Njc4OWFiY2RlZg==", "c2hvcnQ=", 1),
		"missing salt": strings.Replace(validMetaYAML(), "salt: MDEyMzQ1Njc4OWFiY2RlZg==\n", "", 1),
		"unknown key":  validMetaYAML() + "extra: 1\n",
		"duplicate key": strings.Replace(
			validMetaYAML(),
			"cipher: aes-256-gcm",
			"cipher: aes-256-gcm\ncipher: aes-256-gcm",
			1,
		),
		"garbage": "not a yaml at all",
	}
	for name, y := range cases {
		if _, err := ParseVaultMeta([]byte(y)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestCheckPinned(t *testing.T) {
	meta, _ := ParseVaultMeta([]byte(validMetaYAML()))
	if err := CheckPinned(meta, nil); err != nil {
		t.Fatalf("no pin: %v", err)
	}
	same := &Pin{SaltB64: meta.SaltB64, Params: meta.Params}
	if err := CheckPinned(meta, same); err != nil {
		t.Fatalf("same pin: %v", err)
	}
	stronger := &Pin{SaltB64: meta.SaltB64, Params: kdf.Params{Time: 2, Memory: 65536, Threads: 4}}
	if err := CheckPinned(meta, stronger); err != nil {
		t.Fatalf("strengthening must be accepted: %v", err)
	}
	weaker := &Pin{SaltB64: meta.SaltB64, Params: kdf.Params{Time: 4, Memory: 65536, Threads: 4}}
	if err := CheckPinned(meta, weaker); err == nil {
		t.Fatal("weakening must be rejected")
	}
	mixed := &Pin{SaltB64: meta.SaltB64, Params: kdf.Params{Time: 5, Memory: 32768, Threads: 4}}
	if err := CheckPinned(meta, mixed); err == nil {
		t.Fatal("mixed change must be rejected")
	}
	otherSalt := &Pin{SaltB64: "QUFBQUFBQUFBQUFBQUFBUEE9PQ==", Params: meta.Params}
	if err := CheckPinned(meta, otherSalt); !errors.Is(err, ErrSaltChanged) {
		t.Fatalf("salt change = %v, want ErrSaltChanged", err)
	}
}

func TestVaultMetaAADAndFingerprint(t *testing.T) {
	m, _ := ParseVaultMeta([]byte(validMetaYAML()))
	want := "psst:v1:argon2id:MDEyMzQ1Njc4OWFiY2RlZg=="
	if string(m.AAD()) != want {
		t.Fatalf("aad = %q, want %q", m.AAD(), want)
	}
	if m.Fingerprint() == "" || !strings.Contains(m.Fingerprint(), m.SaltB64) {
		t.Fatalf("fingerprint = %q", m.Fingerprint())
	}
}

func TestSecretFileCodec(t *testing.T) {
	iv := bytes.Repeat([]byte{7}, 12)
	ct := []byte("ciphertext-bytes")
	enc := EncodeSecretFile(ct, iv)
	if !bytes.HasSuffix(enc, []byte("\n")) {
		t.Fatal("newline terminated")
	}
	gotCT, gotIV, err := DecodeSecretFile(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(gotCT, ct) || !bytes.Equal(gotIV, iv) {
		t.Fatal("roundtrip mismatch")
	}
	if _, _, err = DecodeSecretFile([]byte("!!!notbase64!!!\n")); err == nil {
		t.Fatal("invalid base64 must error")
	}
	if _, _, err = DecodeSecretFile([]byte("c2hvcnQ=\n")); err == nil {
		t.Fatal("IV < 12 bytes must error")
	}
}

func TestSecretPath(t *testing.T) {
	p, err := SecretPath("/repo/secrets", "API_KEY", "")
	if err != nil || p != "/repo/secrets/API_KEY.enc" {
		t.Fatalf("root path = %q, %v", p, err)
	}
	p, err = SecretPath("/repo/secrets", "API_KEY", "prod")
	if err != nil || p != "/repo/secrets/prod/API_KEY.enc" {
		t.Fatalf("tag path = %q, %v", p, err)
	}
	for _, bad := range []struct{ name, tag string }{
		{"api_key", ""},
		{"API-KEY", ""},
		{"../evil", ""},
		{"API_KEY", "../evil"},
		{"API_KEY", "Prod"},
		{"API_KEY", "my tag"},
	} {
		if _, err = SecretPath("/repo/secrets", bad.name, bad.tag); err == nil {
			t.Fatalf("name=%q tag=%q must error", bad.name, bad.tag)
		}
	}
}

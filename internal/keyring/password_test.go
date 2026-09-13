package keyring

import (
	"testing"
)

func TestPasswordProviderEnv(t *testing.T) {
	t.Setenv("PSST_PASSWORD", "test-password")
	p := NewPasswordProvider(nil, false)
	raw, err := p.GetRawKey("psst", "vault-key")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(raw) != "test-password" {
		t.Fatalf("raw = %q", raw)
	}
	if !p.IsAvailable() {
		t.Fatal("available")
	}
	if err := p.SetKey("psst", "vault-key", []byte("x")); err == nil {
		t.Fatal("SetKey must fail")
	}
}

func TestPasswordProviderEmptyFails(t *testing.T) {
	t.Setenv("PSST_PASSWORD", "")
	p := NewPasswordProvider(nil, false)
	if _, err := p.GetRawKey("psst", "vault-key"); err == nil {
		t.Fatal("empty password must error")
	}
	if p.IsAvailable() {
		t.Fatal("not available without env or prompt")
	}
}

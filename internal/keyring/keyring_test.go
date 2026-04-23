package keyring

import (
	"os"
	"testing"

	"github.com/aatumaykin/psst/internal/crypto"
)

func TestEnvVarProviderGetKey(t *testing.T) {
	enc := crypto.NewAESGCM()
	p := &EnvVarProvider{enc: enc}

	os.Setenv("PSST_PASSWORD", "test-password")
	defer os.Unsetenv("PSST_PASSWORD")

	key, err := p.GetKey("psst", "vault-key")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestEnvVarProviderNotAvailable(t *testing.T) {
	enc := crypto.NewAESGCM()
	p := &EnvVarProvider{enc: enc}

	os.Unsetenv("PSST_PASSWORD")

	if p.IsAvailable() {
		t.Fatal("should not be available without PSST_PASSWORD")
	}
}

func TestEnvVarProviderSetKeyNoop(t *testing.T) {
	enc := crypto.NewAESGCM()
	p := &EnvVarProvider{enc: enc}

	err := p.SetKey("psst", "vault-key", nil)
	if err != nil {
		t.Fatalf("SetKey should be a no-op for env var provider, got: %v", err)
	}
}

func TestEnvVarProviderAvailable(t *testing.T) {
	enc := crypto.NewAESGCM()
	p := &EnvVarProvider{enc: enc}

	os.Setenv("PSST_PASSWORD", "test")
	defer os.Unsetenv("PSST_PASSWORD")

	if !p.IsAvailable() {
		t.Fatal("should be available with PSST_PASSWORD set")
	}
}

func TestEnvVarProviderGenerateKey(t *testing.T) {
	enc := crypto.NewAESGCM()
	p := &EnvVarProvider{enc: enc}

	key, err := p.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

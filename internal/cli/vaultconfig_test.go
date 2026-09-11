package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aatumaykin/psst/internal/crypto"
)

func mustParams(t *testing.T) crypto.KDFParams {
	t.Helper()
	return crypto.DefaultKDFParams()
}

func TestVaultConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := VaultConfig{Storage: "git", Remote: "git@host:vault.git", HasPin: true, PinSalt: "c2FsdA==", PinKDF: mustParams(t)}
	if err := SaveVaultConfig(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadVaultConfig(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Storage != "git" || got.Remote != "git@host:vault.git" || !got.HasPin || got.PinSalt != "c2FsdA==" {
		t.Fatalf("roundtrip = %+v", got)
	}
	if got.PinKDF != crypto.DefaultKDFParams() {
		t.Fatalf("pin kdf = %+v", got.PinKDF)
	}
	if fi, err := os.Stat(filepath.Join(dir, "config.yaml")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("config perms: %v %v", fi, err)
	}
}

func TestVaultConfigMissing(t *testing.T) {
	got, err := LoadVaultConfig(t.TempDir())
	if err != nil || got.Storage != "" {
		t.Fatalf("missing config: %+v %v", got, err)
	}
}

func TestResolveStorage(t *testing.T) {
	dir := t.TempDir()
	if s, _ := ResolveStorage("", dir); s != "sqlite" {
		t.Fatalf("empty dir = %q", s)
	}
	os.WriteFile(filepath.Join(dir, "vault.db"), nil, 0600)
	if s, _ := ResolveStorage("", dir); s != "sqlite" {
		t.Fatal("vault.db autodetect")
	}
	os.MkdirAll(filepath.Join(dir, "repo"), 0755)
	if _, err := ResolveStorage("", dir); err == nil {
		t.Fatal("conflicting markers must error")
	}
	dir2 := t.TempDir()
	os.MkdirAll(filepath.Join(dir2, "repo"), 0755)
	os.WriteFile(filepath.Join(dir2, "repo", "psst.yaml"), []byte("version: 1\n"), 0600)
	if s, _ := ResolveStorage("", dir2); s != "git" {
		t.Fatal("repo autodetect")
	}
	SaveVaultConfig(dir2, VaultConfig{Storage: "sqlite"})
	if s, _ := ResolveStorage("", dir2); s != "sqlite" {
		t.Fatal("config beats autodetect")
	}
	if s, _ := ResolveStorage("git", dir2); s != "git" {
		t.Fatal("flag beats config")
	}
	if _, err := ResolveStorage("bogus", dir2); err == nil {
		t.Fatal("invalid flag value must error")
	}
}

func TestRemoteSchemePolicy(t *testing.T) {
	if err := ValidateRemoteScheme("", false); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if err := ValidateRemoteScheme("git://host/vault.git", true); err == nil {
		t.Fatal("git:// must always be rejected")
	}
	if err := ValidateRemoteScheme("http://host/vault.git", false); err == nil {
		t.Fatal("http:// rejected without flag")
	}
	if err := ValidateRemoteScheme("http://host/vault.git", true); err != nil {
		t.Fatalf("http with flag: %v", err)
	}
	if err := ValidateRemoteScheme("git@host:vault.git", false); err != nil {
		t.Fatalf("ssh: %v", err)
	}
	if err := ValidateRemoteScheme("https://host/vault.git", false); err != nil {
		t.Fatalf("https: %v", err)
	}
	if err := ValidateRemoteScheme("/path/to/vault.git", false); err != nil {
		t.Fatalf("local path: %v", err)
	}
}

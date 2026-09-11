package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/store"
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

func TestOpenVaultStoreLoadPinsFresh(t *testing.T) {
	envDir := filepath.Join(t.TempDir(), "env")
	repo := filepath.Join(envDir, "repo")
	gs, err := store.NewGitStore(repo, store.GitOptions{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := gs.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	s, _, err := OpenVaultStore(envDir, "git", "", false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	cfg, err := LoadVaultConfig(envDir)
	if err != nil {
		t.Fatalf("cfg: %v", err)
	}
	cfg.PinSalt = "AAAAAAAAAAAAAAAAAAAAAA=="
	if err := SaveVaultConfig(envDir, *cfg); err != nil {
		t.Fatalf("save cfg: %v", err)
	}
	err = s.InitSchema()
	if !errors.Is(err, store.ErrSaltChanged) {
		t.Fatalf("InitSchema after pin tamper = %v, want ErrSaltChanged", err)
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
	if err := ValidateRemoteScheme(t.TempDir(), false); err != nil {
		t.Fatalf("local path: %v", err)
	}
	if err := ValidateRemoteScheme("/nonexistent/vault.git", false); err == nil {
		t.Fatal("nonexistent path must be rejected")
	}
	if err := ValidateRemoteScheme("ext::sh -c id", false); err == nil {
		t.Fatal("ext:: must be rejected")
	}
	if err := ValidateRemoteScheme("ftp://host/vault.git", false); err == nil {
		t.Fatal("unknown scheme must be rejected")
	}
}

package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aatumaykin/psst/internal/crypto"
)

func newGitStore(t *testing.T) (*GitStore, string) {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	g, err := NewGitStore(repo, GitOptions{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := g.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	return g, repo
}

func hasFile(t *testing.T, g *GitStore, rel string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(g.repoDir, rel))
	return err == nil
}

func TestGitStoreCRUD(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("API_KEY", []byte("ct1"), iv, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := g.SetSecret("DB_PASS", []byte("ct2"), iv, []string{"prod"}); err != nil {
		t.Fatalf("set tagged: %v", err)
	}
	sec, err := g.GetSecret("DB_PASS")
	if err != nil || sec == nil {
		t.Fatalf("get: %v %v", sec, err)
	}
	if len(sec.Tags) != 1 || sec.Tags[0] != "prod" {
		t.Fatalf("tags = %v", sec.Tags)
	}
	if sec.Name != "DB_PASS" || !hasFile(t, g, filepath.Join("secrets", "prod", "DB_PASS.enc")) {
		t.Fatalf("file layout wrong: %s", sec.Name)
	}
	all, err := g.GetAllSecrets()
	if err != nil || len(all) != 2 {
		t.Fatalf("all = %v %v", all, err)
	}
	metas, err := g.ListSecrets()
	if err != nil || len(metas) != 2 {
		t.Fatalf("list = %v %v", metas, err)
	}
	if err := g.DeleteSecret("API_KEY"); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if sec, _ = g.GetSecret("API_KEY"); sec != nil {
		t.Fatal("deleted secret must be gone")
	}
}

func TestGitStoreMultiTagRejected(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, []string{"a", "b"}); err == nil {
		t.Fatal("multi-tag must fail closed")
	}
}

func TestGitStoreRejectsInvalidNameLookups(t *testing.T) {
	g, repo := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	if sec, err := g.GetSecret("../KEY"); err != nil || sec != nil {
		t.Fatalf("invalid name must be not-found, got %v %v", sec, err)
	}
	if err := g.DeleteSecret("../psst.yaml"); err == nil {
		t.Fatal("invalid name delete must fail")
	}
	if _, err := os.Stat(filepath.Join(repo, "psst.yaml")); err != nil {
		t.Fatalf("psst.yaml must survive traversal attempt: %v", err)
	}
}

func TestGitStoreTagReplaceMovesFile(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, []string{"prod"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := g.SetSecret("KEY", []byte("ct"), iv, []string{"test"}); err != nil {
		t.Fatalf("retag: %v", err)
	}
	if _, err := os.Stat(filepath.Join(g.repoDir, "secrets", "prod", "KEY.enc")); !os.IsNotExist(err) {
		t.Fatal("old tag dir copy must be removed")
	}
	if _, err := os.Stat(filepath.Join(g.repoDir, "secrets", "test", "KEY.enc")); err != nil {
		t.Fatalf("new path: %v", err)
	}
}

func TestGitStoreExecTxBatch(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	err := g.ExecTx(func() error {
		for _, n := range []string{"A1", "B2", "C3"} {
			if err := g.SetSecret(n, []byte("ct"), iv, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	out, err := NewGitRunner(g.repoDir).Run("log", "--oneline")
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	if got := countNonEmptyLines(out); got != 2 {
		t.Fatalf("commits = %d, want 2 (init + one batch): %s", got, out)
	}
}

func TestGitStoreMeta(t *testing.T) {
	g, _ := newGitStore(t)
	v, err := g.GetMeta("kdf_version")
	if err != nil || v != "2" {
		t.Fatalf("kdf_version = %q %v", v, err)
	}
	salt, _ := g.GetMeta("kdf_salt")
	if salt == "" {
		t.Fatal("salt exposed")
	}
	if aad, _ := g.GetMeta("vault_aad"); aad == "" {
		t.Fatal("aad exposed")
	}
	if tv, _ := g.GetMeta("kdf_time"); tv != "3" {
		t.Fatalf("kdf_time = %q", tv)
	}
	if _, err := g.GetMeta("nope"); err != nil {
		t.Fatalf("unknown key must return empty: %v", err)
	}
	if fp := g.FingerprintOfCurrent(); fp == "" {
		t.Fatal("fingerprint")
	}
}

func TestGitStoreInitSchemaNonDestructive(t *testing.T) {
	g, repo := newGitStore(t)
	if err := g.InitSchema(); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "psst.yaml"), []byte("version: 9\n"), 0600); err != nil {
		t.Fatal(err)
	}
	g2, err := NewGitStore(repo, GitOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := g2.InitSchema(); err == nil {
		t.Fatal("corrupted psst.yaml must be a hard error")
	}
}

func TestGitStoreWalkIgnoresForeignPaths(t *testing.T) {
	g, repo := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, []string{"prod"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "secrets", "BadTag"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "secrets", "BadTag", "X.enc"), []byte("junk\n"), 0600); err != nil {
		t.Fatal(err)
	}
	metas, err := g.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 1 || metas[0].Name != "KEY" {
		t.Fatalf("walk must ignore foreign entries: %v", metas)
	}
}

func TestGitStoreSetMetaKDFParams(t *testing.T) {
	g, repo := newGitStore(t)
	if err := g.SetMeta("kdf_time", "4"); err != nil {
		t.Fatalf("setmeta: %v", err)
	}
	if tv, _ := g.GetMeta("kdf_time"); tv != "4" {
		t.Fatalf("kdf_time = %q", tv)
	}
	data, err := os.ReadFile(filepath.Join(repo, "psst.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseVaultMeta(data)
	if err != nil {
		t.Fatalf("psst.yaml must stay valid: %v", err)
	}
	if m.Params.Time != 4 {
		t.Fatalf("persisted time = %d", m.Params.Time)
	}
}

func countNonEmptyLines(s string) int {
	n := 0
	line := ""
	for _, c := range s {
		if c == '\n' {
			if line != "" {
				n++
			}
			line = ""
			continue
		}
		line += string(c)
	}
	if line != "" {
		n++
	}
	return n
}

var _ = crypto.DefaultKDFParams

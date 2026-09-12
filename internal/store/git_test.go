package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/kdf"
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

func newSeededStore(t *testing.T, remote string) *GitStore {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	g, err := NewGitStore(repo, GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := g.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	return g
}

func cloneVault(t *testing.T, remote string) *GitStore {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "clone")
	g, err := CloneGitVault(remote, repo, GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if err := g.InitSchema(); err != nil {
		t.Fatalf("init clone: %v", err)
	}
	return g
}

func TestGitStoreSyncRoundTrip(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newSeededStore(t, remote)
	iv := make([]byte, 12)
	if err := g1.SetSecret("KEY", []byte("ct"), iv, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	g2 := cloneVault(t, remote)
	if err := g2.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	sec, err := g2.GetSecret("KEY")
	if err != nil || sec == nil {
		t.Fatalf("get after sync: %v %v", sec, err)
	}
}

func TestGitStoreConflictFailsClosed(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newSeededStore(t, remote)
	g2 := cloneVault(t, remote)
	iv := make([]byte, 12)
	if err := g1.SetSecret("KEY", []byte("one"), iv, nil); err != nil {
		t.Fatalf("set one: %v", err)
	}
	if err := g2.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := g2.SetSecret("KEY", []byte("two"), iv, nil); err != nil {
		t.Fatalf("set two: %v", err)
	}
	err := g1.SetSecret("KEY", []byte("three"), iv, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("same-key race must fail closed with ErrConflict, got %v", err)
	}
}

func TestGitStoreDifferentKeysRebase(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newSeededStore(t, remote)
	g2 := cloneVault(t, remote)
	iv := make([]byte, 12)
	if err := g1.SetSecret("A1", []byte("x"), iv, nil); err != nil {
		t.Fatalf("set A1: %v", err)
	}
	if err := g2.SetSecret("B2", []byte("y"), iv, nil); err != nil {
		t.Fatalf("set B2 must succeed after rebase: %v", err)
	}
	g3 := cloneVault(t, remote)
	if _, err := g3.GetSecret("A1"); err != nil {
		t.Fatalf("A1 lost: %v", err)
	}
	if _, err := g3.GetSecret("B2"); err != nil {
		t.Fatalf("B2 lost: %v", err)
	}
}

func TestGitStoreDiscardLocalRecovers(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newSeededStore(t, remote)
	g2 := cloneVault(t, remote)
	iv := make([]byte, 12)
	if err := g1.SetSecret("KEY", []byte("local"), iv, nil); err != nil {
		t.Fatalf("set local: %v", err)
	}
	if err := g2.SetSecret("KEY", []byte("remote"), iv, nil); err != nil {
		t.Fatalf("set remote: %v", err)
	}
	err := g1.SetSecret("OTHER", []byte("z"), iv, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict deadlock, got %v", err)
	}
	if err := g1.DiscardLocal(); err != nil {
		t.Fatalf("discard: %v", err)
	}
	if err := g1.SetSecret("OTHER", []byte("z"), iv, nil); err != nil {
		t.Fatalf("recovered: %v", err)
	}
}

func TestGitStoreStaleKeyAborts(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newSeededStore(t, remote)
	iv := make([]byte, 12)
	if err := g1.SetSecret("KEY", []byte("ct"), iv, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	g1.SetUnlockedFingerprint(g1.FingerprintOfCurrent())

	g2 := cloneVault(t, remote)
	if err := g2.SetMeta("kdf_time", "4"); err != nil {
		t.Fatalf("migrate params remotely: %v", err)
	}

	err := g1.SetSecret("KEY2", []byte("ct"), iv, nil)
	if !errors.Is(err, ErrRemoteMetaChanged) {
		t.Fatalf("stale write = %v, want ErrRemoteMetaChanged", err)
	}
}

func TestGitStoreSyncConflictErrors(t *testing.T) {
	remote := newBareRemote(t)
	g1 := newSeededStore(t, remote)
	g2 := cloneVault(t, remote)
	iv := make([]byte, 12)
	_ = g1.SetSecret("KEY", []byte("a"), iv, nil)
	_ = g2.SetSecret("KEY", []byte("b"), iv, nil)
	if err := g1.Sync(); !errors.Is(err, ErrConflict) {
		t.Fatalf("sync on conflicted clone = %v, want ErrConflict", err)
	}
}

func TestGitStoreSyncNoRemote(t *testing.T) {
	g, _ := newGitStore(t)
	if err := g.Sync(); !errors.Is(err, ErrNoRemote) {
		t.Fatalf("local-only sync = %v, want ErrNoRemote", err)
	}
}

func TestGitStoreGetHistory(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	_ = g.SetSecret("KEY", []byte("v1"), iv, nil)
	_ = g.SetSecret("KEY", []byte("v2"), iv, nil)
	_ = g.SetSecret("KEY", []byte("v3"), iv, nil)
	h, err := g.GetHistory("KEY")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(h) != 2 {
		t.Fatalf("entries = %d, want 2 (HEAD excluded)", len(h))
	}
	if h[0].Version != 2 || h[1].Version != 1 {
		t.Fatalf("versions = %d,%d want 2,1 (DESC, oldest-based)", h[0].Version, h[1].Version)
	}
	if !bytes.Equal(h[1].EncryptedValue, []byte("v1")) {
		t.Fatal("oldest entry must carry v1 ciphertext")
	}
	if h[0].Author == "" {
		t.Fatal("author populated")
	}
	if h[0].ID != 0 {
		t.Fatal("ID zero for git")
	}
}

func TestGitStoreOfflineRead(t *testing.T) {
	remote := newBareRemote(t)
	g := newSeededStore(t, remote)
	iv := make([]byte, 12)
	_ = g.SetSecret("KEY", []byte("ct"), iv, nil)
	if _, err := NewGitRunner(g.repoDir).Run("config", "remote.origin.url", "/nonexistent/remote.git"); err != nil {
		t.Fatal(err)
	}
	sec, err := g.GetSecret("KEY")
	if err != nil || sec == nil {
		t.Fatalf("offline read must work: %v %v", sec, err)
	}
}

func TestGitStoreDates(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	_ = g.SetSecret("KEY", []byte("ct"), iv, nil)
	metas, err := g.ListSecrets()
	if err != nil || len(metas) != 1 {
		t.Fatalf("list: %v %v", metas, err)
	}
	if metas[0].CreatedAt.IsZero() || metas[0].UpdatedAt.IsZero() {
		t.Fatalf("dates must be populated: %+v", metas[0])
	}
	sec, _ := g.GetSecret("KEY")
	if sec.CreatedAt.IsZero() {
		t.Fatal("GetSecret dates populated")
	}
}

func TestCloneEmptyRemoteOnboarding(t *testing.T) {
	remote := newBareRemote(t)
	repo := filepath.Join(t.TempDir(), "repo")
	g, err := CloneGitVault(remote, repo, GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("clone empty: %v", err)
	}
	if err := g.InitSchema(); err != nil {
		t.Fatalf("onboarding init must create vault: %v", err)
	}
	if g2 := cloneVault(t, remote); g2 == nil {
		t.Fatal("second machine sees vault")
	}
}

func TestGitStoreListUpdatedBy(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	metas, err := g.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("metas = %d", len(metas))
	}
	if !strings.HasPrefix(metas[0].UpdatedBy, "psst/") {
		t.Fatalf("updatedBy = %q, want psst/<hostname>", metas[0].UpdatedBy)
	}
}

func newClonedStore(t *testing.T, remote string) *GitStore {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	g, err := NewGitStore(repo, GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := g.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := g.pushAll(); err != nil {
		t.Fatalf("push: %v", err)
	}
	return g
}

func TestGitStoreHasRemote(t *testing.T) {
	g := newClonedStore(t, newBareRemote(t))
	if !g.HasRemote() {
		t.Fatal("cloned store must report remote")
	}
	local, _ := newGitStore(t)
	if local.HasRemote() {
		t.Fatal("local-only store must not report remote")
	}
}

func TestGitStorePushFailedSentinel(t *testing.T) {
	remote := newBareRemote(t)
	g := newClonedStore(t, remote)
	if err := os.Chmod(remote, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(remote, 0o755) })
	iv := make([]byte, 12)
	err := g.SetSecret("KEY", []byte("ct"), iv, nil)
	if err == nil {
		t.Fatal("push to read-only remote must fail")
	}
	if !errors.Is(err, ErrPushFailed) {
		t.Fatalf("err = %v, want ErrPushFailed", err)
	}
	if !strings.Contains(err.Error(), "run `psst sync` later") {
		t.Fatalf("message text changed: %v", err)
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

var _ = kdf.Default

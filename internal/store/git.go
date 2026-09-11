package store

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/aatumaykin/psst/internal/crypto"
)

type GitOptions struct {
	Remote              string
	AllowInsecureRemote bool
	LoadPins            func() *Pin
	SavePins            func(Pin) error
}

type GitStore struct {
	mu         sync.Mutex
	repoDir    string
	opts       GitOptions
	git        *GitRunner
	meta       *VaultMeta
	metaErr    error
	txDepth    int
	dirty      bool
	unlockedFP string
}

func NewGitStore(repoDir string, opts GitOptions) (*GitStore, error) {
	g := &GitStore{repoDir: repoDir, opts: opts, git: NewGitRunner(repoDir)}
	data, err := os.ReadFile(filepath.Join(repoDir, "psst.yaml"))
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read vault metadata: %w", err)
		}
		return g, nil
	}
	m, perr := ParseVaultMeta(data)
	if perr != nil {
		g.metaErr = perr
		return g, nil
	}
	g.meta = m
	return g, nil
}

func (g *GitStore) SetUnlockedFingerprint(fp string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.unlockedFP = fp
}

func (g *GitStore) FingerprintOfCurrent() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.meta == nil {
		return ""
	}
	return g.meta.Fingerprint()
}

func (g *GitStore) InitSchema() error {
	if g.metaErr != nil {
		return fmt.Errorf("vault metadata missing or invalid; refusing to regenerate (salt would invalidate all secrets): %w", g.metaErr)
	}
	_, gitErr := os.Stat(filepath.Join(g.repoDir, ".git"))
	if g.meta != nil {
		if gitErr != nil {
			return fmt.Errorf("vault repo is corrupted: psst.yaml without .git")
		}
		if g.opts.LoadPins != nil {
			if err := CheckPinned(g.meta, g.opts.LoadPins()); err != nil {
				return fmt.Errorf("vault metadata changed since last open: %w", err)
			}
		}
		return nil
	}
	if gitErr == nil {
		return fmt.Errorf("vault metadata missing or invalid; refusing to regenerate (salt would invalidate all secrets)")
	}
	if err := os.MkdirAll(g.repoDir, 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	if _, err := g.git.Run("init"); err != nil {
		return fmt.Errorf("git init: %w", err)
	}
	host, _ := os.Hostname()
	if _, err := g.git.Run("config", "user.name", "psst/"+host); err != nil {
		return fmt.Errorf("git config user.name: %w", err)
	}
	if _, err := g.git.Run("config", "user.email", "psst@"+host); err != nil {
		return fmt.Errorf("git config user.email: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	g.meta = NewVaultMeta(base64.StdEncoding.EncodeToString(salt), crypto.DefaultKDFParams())
	metaPath := filepath.Join(g.repoDir, "psst.yaml")
	if err := os.WriteFile(metaPath, g.meta.Encode(), 0o600); err != nil {
		return fmt.Errorf("write vault metadata: %w", err)
	}
	if _, err := g.git.Run("add", "psst.yaml"); err != nil {
		return fmt.Errorf("git add psst.yaml: %w", err)
	}
	g.mu.Lock()
	g.dirty = true
	g.mu.Unlock()
	if err := g.commit("psst: init"); err != nil {
		return err
	}
	if g.opts.SavePins != nil {
		if err := g.opts.SavePins(Pin{SaltB64: g.meta.SaltB64, Params: g.meta.Params}); err != nil {
			return fmt.Errorf("save pins: %w", err)
		}
	}
	return nil
}

type gitEntry struct {
	path string
	name string
	tag  string
}

func (g *GitStore) secretsRoot() string {
	return filepath.Join(g.repoDir, "secrets")
}

func (g *GitStore) locate(name string) (string, string, bool) {
	if !ValidSecretName.MatchString(name) {
		return "", "", false
	}
	root := g.secretsRoot()
	if fileExists(filepath.Join(root, name+".enc")) {
		return filepath.Join(root, name+".enc"), "", true
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", "", false
	}
	for _, e := range entries {
		if !e.IsDir() || !ValidTag.MatchString(e.Name()) {
			continue
		}
		p := filepath.Join(root, e.Name(), name+".enc")
		if fileExists(p) {
			return p, e.Name(), true
		}
	}
	return "", "", false
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func (g *GitStore) walkSecrets() ([]gitEntry, error) {
	root := g.secretsRoot()
	var entries []gitEntry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			relDir, rerr := filepath.Rel(root, path)
			if rerr != nil || strings.Contains(filepath.ToSlash(relDir), "/") || !ValidTag.MatchString(filepath.Base(relDir)) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		dir, base := filepath.Split(rel)
		if dir != "" {
			tag := filepath.ToSlash(strings.TrimSuffix(dir, "/"))
			if strings.Contains(tag, "/") || !ValidTag.MatchString(tag) {
				return nil
			}
			name := strings.TrimSuffix(base, ".enc")
			if !ValidSecretName.MatchString(name) {
				return nil
			}
			entries = append(entries, gitEntry{path: path, name: name, tag: tag})
			return nil
		}
		name := strings.TrimSuffix(base, ".enc")
		if !ValidSecretName.MatchString(name) || name+".enc" != base {
			return nil
		}
		entries = append(entries, gitEntry{path: path, name: name, tag: ""})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("walk secrets: %w", err)
	}
	return entries, nil
}

func (g *GitStore) pullForWrite() error {
	return nil
}

func (g *GitStore) push() error {
	return nil
}

func (g *GitStore) SyncPullRead() (bool, error) {
	return false, nil
}

func (g *GitStore) mutate(msg string, op func() error) error {
	g.mu.Lock()
	nested := g.txDepth > 0
	g.mu.Unlock()
	if nested {
		return op()
	}
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	if err := g.pullForWrite(); err != nil {
		return err
	}
	g.mu.Lock()
	g.txDepth++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.txDepth--
		g.mu.Unlock()
	}()
	if err := op(); err != nil {
		return err
	}
	if err := g.commit(msg); err != nil {
		return err
	}
	return g.push()
}

func (g *GitStore) commit(msg string) error {
	g.mu.Lock()
	dirty := g.dirty
	g.mu.Unlock()
	if !dirty {
		return nil
	}
	_, err := g.git.Run("commit", "-m", msg)
	g.mu.Lock()
	g.dirty = false
	g.mu.Unlock()
	if err != nil {
		if strings.Contains(err.Error(), "nothing to commit") {
			return nil
		}
		return fmt.Errorf("git commit: %w", err)
	}
	return nil
}

func (g *GitStore) markDirty() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.dirty = true
}

func (g *GitStore) ExecTx(fn func() error) error {
	g.mu.Lock()
	nested := g.txDepth > 0
	g.mu.Unlock()
	if nested {
		return fn()
	}
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	if err := g.pullForWrite(); err != nil {
		return err
	}
	g.mu.Lock()
	g.txDepth++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.txDepth--
		g.mu.Unlock()
	}()
	if err := fn(); err != nil {
		return err
	}
	if err := g.commit("psst: batch"); err != nil {
		return err
	}
	return g.push()
}

func (g *GitStore) SetSecret(name string, encValue, iv []byte, tags []string) error {
	tag := ""
	switch len(tags) {
	case 0:
	case 1:
		tag = tags[0]
		if !ValidTag.MatchString(tag) {
			return fmt.Errorf("invalid tag %q", tag)
		}
	default:
		return fmt.Errorf("git vault supports a single tag")
	}
	oldPath, oldTag, had := g.locate(name)
	path, err := SecretPath(g.secretsRoot(), name, tag)
	if err != nil {
		return err
	}
	msg := "psst: set " + name
	if had && oldTag != tag {
		msg = "psst: tag " + name
	}
	return g.mutate(msg, func() error {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create secret directory: %w", err)
		}
		if err := os.WriteFile(path, EncodeSecretFile(encValue, iv), 0o600); err != nil {
			return fmt.Errorf("write secret: %w", err)
		}
		rel, err := filepath.Rel(g.repoDir, path)
		if err != nil {
			return fmt.Errorf("secret path: %w", err)
		}
		if _, err := g.git.Run("add", rel); err != nil {
			return fmt.Errorf("git add %s: %w", rel, err)
		}
		if had && oldPath != path {
			if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove old secret: %w", err)
			}
			oldRel, err := filepath.Rel(g.repoDir, oldPath)
			if err != nil {
				return fmt.Errorf("old secret path: %w", err)
			}
			if _, err := g.git.Run("add", oldRel); err != nil {
				return fmt.Errorf("git add %s: %w", oldRel, err)
			}
		}
		g.markDirty()
		return nil
	})
}

func (g *GitStore) GetSecret(name string) (*StoredSecret, error) {
	diverged, err := g.SyncPullRead()
	if err != nil {
		return nil, err
	}
	path, tag, ok := g.locate(name)
	if !ok {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secret %q: %w", name, err)
	}
	ct, iv, err := DecodeSecretFile(data)
	if err != nil {
		return nil, fmt.Errorf("decode secret %q: %w", name, err)
	}
	var secretTags []string
	if tag != "" {
		secretTags = []string{tag}
	}
	if diverged {
		fmt.Fprintln(os.Stderr, "psst: warning: local clone has unpushed changes; run psst sync")
	}
	return &StoredSecret{Name: name, EncryptedValue: ct, IV: iv, Tags: secretTags}, nil
}

func (g *GitStore) GetAllSecrets() ([]StoredSecret, error) {
	if _, err := g.SyncPullRead(); err != nil {
		return nil, err
	}
	entries, err := g.walkSecrets()
	if err != nil {
		return nil, err
	}
	result := make([]StoredSecret, 0, len(entries))
	for _, e := range entries {
		data, err := os.ReadFile(e.path)
		if err != nil {
			return nil, fmt.Errorf("read secret %q: %w", e.name, err)
		}
		ct, iv, err := DecodeSecretFile(data)
		if err != nil {
			return nil, fmt.Errorf("decode secret file %s: %w", e.path, err)
		}
		var secretTags []string
		if e.tag != "" {
			secretTags = []string{e.tag}
		}
		result = append(result, StoredSecret{Name: e.name, EncryptedValue: ct, IV: iv, Tags: secretTags})
	}
	return result, nil
}

func (g *GitStore) ListSecrets() ([]SecretMeta, error) {
	if _, err := g.SyncPullRead(); err != nil {
		return nil, err
	}
	entries, err := g.walkSecrets()
	if err != nil {
		return nil, err
	}
	result := make([]SecretMeta, 0, len(entries))
	for _, e := range entries {
		var secretTags []string
		if e.tag != "" {
			secretTags = []string{e.tag}
		}
		result = append(result, SecretMeta{Name: e.name, Tags: secretTags})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (g *GitStore) DeleteSecret(name string) error {
	path, _, ok := g.locate(name)
	if !ok {
		return fmt.Errorf("secret %q not found", name)
	}
	return g.mutate("psst: rm "+name, func() error {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove secret: %w", err)
		}
		rel, err := filepath.Rel(g.repoDir, path)
		if err != nil {
			return fmt.Errorf("secret path: %w", err)
		}
		if _, err := g.git.Run("add", rel); err != nil {
			return fmt.Errorf("git add %s: %w", rel, err)
		}
		g.markDirty()
		return nil
	})
}

func (g *GitStore) GetHistory(name string) ([]HistoryEntry, error) {
	return nil, nil
}

func (g *GitStore) AddHistory(name string, version int, encValue, iv []byte, tags []string) error {
	return nil
}

func (g *GitStore) PruneHistory(name string, keepVersions int) error {
	return nil
}

func (g *GitStore) DeleteHistory(name string) error {
	return nil
}

func (g *GitStore) Close() error {
	return nil
}

func (g *GitStore) GetMeta(key string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch key {
	case "kdf_version":
		return "2", nil
	case "kdf_salt":
		if g.meta == nil {
			return "", g.metaErr
		}
		return g.meta.SaltB64, nil
	case "kdf_time":
		if g.meta == nil {
			return "", g.metaErr
		}
		return strconv.FormatUint(uint64(g.meta.Params.Time), 10), nil
	case "kdf_memory":
		if g.meta == nil {
			return "", g.metaErr
		}
		return strconv.FormatUint(uint64(g.meta.Params.Memory), 10), nil
	case "kdf_threads":
		if g.meta == nil {
			return "", g.metaErr
		}
		return strconv.FormatUint(uint64(g.meta.Params.Threads), 10), nil
	case "vault_aad":
		if g.meta == nil {
			return "", g.metaErr
		}
		return string(g.meta.AAD()), nil
	case "storage":
		return "git", nil
	}
	return "", nil
}

func (g *GitStore) SetMeta(key, value string) error {
	switch key {
	case "kdf_time", "kdf_memory", "kdf_threads":
	default:
		return nil
	}
	g.mu.Lock()
	if g.meta == nil {
		err := g.metaErr
		g.mu.Unlock()
		if err != nil {
			return fmt.Errorf("vault metadata missing or invalid: %w", err)
		}
		return fmt.Errorf("vault metadata missing or invalid")
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		g.mu.Unlock()
		return fmt.Errorf("invalid %s value %q: %w", key, value, err)
	}
	switch key {
	case "kdf_time":
		g.meta.Params.Time = uint32(n)
	case "kdf_memory":
		g.meta.Params.Memory = uint32(n)
	case "kdf_threads":
		g.meta.Params.Threads = uint8(n)
	}
	encoded := g.meta.Encode()
	g.mu.Unlock()
	return g.mutate("psst: migrate", func() error {
		metaPath := filepath.Join(g.repoDir, "psst.yaml")
		if err := os.WriteFile(metaPath, encoded, 0o600); err != nil {
			return fmt.Errorf("write vault metadata: %w", err)
		}
		if _, err := g.git.Run("add", "psst.yaml"); err != nil {
			return fmt.Errorf("git add psst.yaml: %w", err)
		}
		g.markDirty()
		return nil
	})
}

var _ SecretStore = (*GitStore)(nil)

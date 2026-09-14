package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aatumaykin/psst/internal/kdf"
)

const (
	saltSize         = 16
	entryFieldParts  = 2
	commitFieldParts = 3
	readLockWait     = 3 * time.Second
)

var (
	ErrNoRemote          = errors.New("no remote configured")
	ErrRemoteMetaChanged = errors.New("vault parameters changed remotely; re-run the command")
	ErrConflict          = errors.New("key changed remotely; re-set the value or run `psst sync --discard-local`")
	ErrPushFailed        = errors.New("push failed")
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
	written    map[string]bool
}

func CloneGitVault(remote, repoDir string, opts GitOptions) (*GitStore, error) {
	abs, err := filepath.Abs(repoDir)
	if err != nil {
		return nil, fmt.Errorf("resolve vault path: %w", err)
	}
	repoDir = abs
	if err = os.MkdirAll(filepath.Dir(repoDir), 0o700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}
	if _, err = NewGitRunner(filepath.Dir(repoDir)).Run("clone", remote, repoDir); err != nil {
		return nil, fmt.Errorf("git clone: %w", err)
	}
	git := NewGitRunner(repoDir)
	if !git.RunOK("log", "-1", "--format=%H") && git.RunOK("log", "-1", "--format=%H", "origin/main") {
		if _, err = git.Run("checkout", "main"); err != nil {
			return nil, fmt.Errorf("checkout main: %w", err)
		}
	}
	g, err := NewGitStore(repoDir, opts)
	if err != nil {
		return nil, err
	}
	if err = g.ensureIdentity(); err != nil {
		return nil, err
	}
	return g, nil
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
		return g, nil //nolint:nilerr // parse error is stashed in metaErr and surfaced by InitSchema
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

func (g *GitStore) ensureIdentityLocked() error {
	host, _ := os.Hostname()
	if _, err := g.git.Run("config", "user.name", "psst/"+host); err != nil {
		return fmt.Errorf("git config user.name: %w", err)
	}
	if _, err := g.git.Run("config", "user.email", "psst@"+host); err != nil {
		return fmt.Errorf("git config user.email: %w", err)
	}
	return nil
}

func (g *GitStore) ensureIdentity() error {
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Unlock() }()
	return g.ensureIdentityLocked()
}

func (g *GitStore) InitSchema() error {
	if g.metaErr != nil {
		return fmt.Errorf(
			"vault metadata missing or invalid; refusing to regenerate (salt would invalidate all secrets): %w",
			g.metaErr,
		)
	}
	_, gitErr := os.Stat(filepath.Join(g.repoDir, ".git"))
	if g.meta != nil {
		if gitErr != nil {
			return errors.New("vault repo is corrupted: psst.yaml without .git")
		}
		return g.checkPinsAndReuse()
	}
	if gitErr == nil && g.hasCommits() {
		return errors.New(
			"vault metadata missing or invalid; refusing to regenerate (salt would invalidate all secrets)",
		)
	}
	return g.initFreshRepo(gitErr != nil)
}

func (g *GitStore) checkPinsAndReuse() error {
	if g.opts.LoadPins != nil {
		pin := g.opts.LoadPins()
		if pin == nil {
			if g.opts.SavePins != nil {
				if err := g.opts.SavePins(Pin{SaltB64: g.meta.SaltB64, Params: g.meta.Params}); err != nil {
					return fmt.Errorf("save pins: %w", err)
				}
			}
		} else {
			if err := CheckPinned(g.meta, pin); err != nil {
				return fmt.Errorf("vault metadata changed since last open: %w", err)
			}
			if g.opts.SavePins != nil && pin.Params != g.meta.Params {
				if err := g.opts.SavePins(Pin{SaltB64: g.meta.SaltB64, Params: g.meta.Params}); err != nil {
					return fmt.Errorf("save pins: %w", err)
				}
				fmt.Fprintln(os.Stderr, "psst: notice: vault KDF parameters strengthened; pin updated")
			}
		}
	}
	if err := g.ensureIdentity(); err != nil {
		return err
	}
	return nil
}

func (g *GitStore) initFreshRepo(needInit bool) error {
	if err := os.MkdirAll(g.repoDir, 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Unlock() }()
	if needInit {
		if _, err = g.git.Run("init", "-b", "main"); err != nil {
			return fmt.Errorf("git init: %w", err)
		}
		if g.opts.Remote != "" {
			if _, err = g.git.Run("config", "remote.origin.url", g.opts.Remote); err != nil {
				return fmt.Errorf("git config remote.origin.url: %w", err)
			}
			if _, err = g.git.Run("config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"); err != nil {
				return fmt.Errorf("git config remote.origin.fetch: %w", err)
			}
		}
	}
	if err = g.ensureIdentityLocked(); err != nil {
		return err
	}
	salt := make([]byte, saltSize)
	if _, err = rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	g.mu.Lock()
	g.meta = NewVaultMeta(base64.StdEncoding.EncodeToString(salt), kdf.Default())
	g.mu.Unlock()
	metaPath := filepath.Join(g.repoDir, "psst.yaml")
	if err = os.WriteFile(metaPath, g.meta.Encode(), 0o600); err != nil {
		return fmt.Errorf("write vault metadata: %w", err)
	}
	if _, err = g.git.Run("add", "psst.yaml"); err != nil {
		return fmt.Errorf("git add psst.yaml: %w", err)
	}
	g.mu.Lock()
	g.dirty = true
	g.mu.Unlock()
	if err = g.commit("psst: init"); err != nil {
		return err
	}
	if err = g.pushAll(); err != nil && !errors.Is(err, ErrNoRemote) {
		return err
	}
	if g.opts.SavePins != nil {
		if err = g.opts.SavePins(Pin{SaltB64: g.meta.SaltB64, Params: g.meta.Params}); err != nil {
			return fmt.Errorf("save pins: %w", err)
		}
	}
	return nil
}

func (g *GitStore) hasUpstream() bool {
	out, err := g.git.Run("status", "-sb")
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(out, "\n")
	return strings.Contains(first, "...")
}

func (g *GitStore) hasCommits() bool {
	return g.git.RunOK("log", "-1", "--format=%H")
}

func (g *GitStore) hasRemote() bool {
	out, err := g.git.Run("config", "--get", "remote.origin.url")
	return err == nil && strings.TrimSpace(out) != ""
}

func (g *GitStore) HasRemote() bool {
	return g.hasRemote()
}

func (g *GitStore) HasUpstream() bool {
	return g.hasUpstream()
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
			if rerr != nil || strings.Contains(filepath.ToSlash(relDir), "/") ||
				!ValidTag.MatchString(filepath.Base(relDir)) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil //nolint:nilerr // unresolvable entries are skipped
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

func (g *GitStore) currentHead() string {
	out, err := g.git.Run("log", "-1", "--format=%H")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (g *GitStore) recordWritten(rel string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.written == nil {
		g.written = make(map[string]bool)
	}
	g.written[filepath.ToSlash(rel)] = true
}

func (g *GitStore) forgetWritten() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.written = nil
}

func (g *GitStore) checkIncomingChanges(oldHead string) error {
	if oldHead == "" {
		return nil
	}
	newHead := g.currentHead()
	if newHead == "" || newHead == oldHead {
		return nil
	}
	if out, err := g.git.Run("log", "--format=%H", newHead+".."+oldHead); err != nil || strings.TrimSpace(out) != "" {
		return nil
	}
	g.mu.Lock()
	written := make(map[string]bool, len(g.written))
	for p := range g.written {
		written[p] = true
	}
	g.mu.Unlock()
	if out, err := g.git.Run("show", "--name-only", "--format=", oldHead); err == nil {
		for line := range strings.SplitSeq(out, "\n") {
			if p := strings.TrimSpace(line); strings.HasPrefix(p, "secrets/") {
				written[p] = true
			}
		}
	}
	if len(written) == 0 {
		return nil
	}
	out, err := g.git.Run("log", "--name-only", "--format=%H", oldHead+".."+newHead)
	if err != nil {
		return nil
	}
	for line := range strings.SplitSeq(out, "\n") {
		p := strings.TrimSpace(line)
		if p != "" && written[p] {
			return ErrConflict
		}
	}
	return nil
}

func (g *GitStore) pullForWrite() error {
	if !g.hasUpstream() {
		return nil
	}
	oldHead := g.currentHead()
	if _, err := g.git.Run("pull", "--rebase", "--autostash"); err != nil {
		_, _ = g.git.Run("rebase", "--abort")
		msg := err.Error()
		if strings.Contains(msg, "CONFLICT") || strings.Contains(msg, "could not apply") ||
			strings.Contains(msg, "Rebase") {
			return ErrConflict
		}
		return fmt.Errorf("pull failed: %w", err)
	}
	if err := g.checkIncomingChanges(oldHead); err != nil {
		return err
	}
	return g.reloadMetaAndCheck()
}

func (g *GitStore) reloadMetaAndCheck() error {
	data, err := os.ReadFile(filepath.Join(g.repoDir, "psst.yaml"))
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("vault metadata missing after pull")
		}
		return fmt.Errorf("vault metadata missing after pull: %w", err)
	}
	newMeta, perr := ParseVaultMeta(data)
	if perr != nil {
		return fmt.Errorf("vault metadata invalid after pull: %w", perr)
	}
	g.mu.Lock()
	unlocked := g.unlockedFP
	g.mu.Unlock()
	if g.opts.LoadPins != nil {
		if pinErr := CheckPinned(newMeta, g.opts.LoadPins()); pinErr != nil {
			if errors.Is(pinErr, ErrSaltChanged) {
				return fmt.Errorf(
					"vault metadata changed since last open: %w; run 'psst sync --accept-rotation' (or re-clone)",
					pinErr,
				)
			}
			return fmt.Errorf("vault metadata changed since last open: %w", pinErr)
		}
	}
	if unlocked != "" && newMeta.Fingerprint() != unlocked {
		return ErrRemoteMetaChanged
	}
	g.mu.Lock()
	g.meta = newMeta
	g.mu.Unlock()
	return nil
}

func (g *GitStore) push() error {
	if !g.hasUpstream() {
		return ErrNoRemote
	}
	if _, err := g.git.Run("push"); err != nil {
		return fmt.Errorf("%w; change is in the local clone, run `psst sync` later: %w", ErrPushFailed, err)
	}
	return nil
}

func (g *GitStore) pushAll() error {
	if !g.hasRemote() {
		return ErrNoRemote
	}
	if _, err := g.git.Run("push", "-u", "origin", "HEAD"); err != nil {
		return fmt.Errorf("%w; change is in the local clone, run `psst sync` later: %w", ErrPushFailed, err)
	}
	return nil
}

func (g *GitStore) SyncPullRead() (bool, error) {
	g.mu.Lock()
	inTx := g.txDepth > 0
	g.mu.Unlock()
	if inTx || !g.hasUpstream() {
		return false, nil
	}
	lock, err := LockRepoWait(g.repoDir, readLockWait)
	if err != nil {
		return false, nil
	}
	defer func() { _ = lock.Unlock() }()
	_, err = g.git.Run("pull", "--ff-only")
	if err == nil {
		if rerr := g.reloadMetaAndCheck(); rerr != nil {
			return false, rerr
		}
		return false, nil
	}
	msg := err.Error()
	if strings.Contains(msg, "Not possible to fast-forward") || strings.Contains(msg, "divergent") {
		return true, nil
	}
	return false, nil
}

func (g *GitStore) Sync() error {
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Unlock() }()
	if !g.hasUpstream() {
		return ErrNoRemote
	}
	oldHead := g.currentHead()
	if _, err = g.git.Run("pull", "--rebase", "--autostash"); err != nil {
		_, _ = g.git.Run("rebase", "--abort")
		msg := err.Error()
		if strings.Contains(msg, "CONFLICT") || strings.Contains(msg, "could not apply") ||
			strings.Contains(msg, "Rebase") {
			return ErrConflict
		}
		return fmt.Errorf("pull failed: %w", err)
	}
	if err = g.checkIncomingChanges(oldHead); err != nil {
		return err
	}
	if err = g.reloadMetaAndCheck(); err != nil {
		return err
	}
	if err = g.push(); err != nil {
		return err
	}
	g.forgetWritten()
	return nil
}

func (g *GitStore) DiscardLocal() error {
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Unlock() }()
	if !g.hasUpstream() {
		return ErrNoRemote
	}
	if err = g.git.RunResetHardUpstream(); err != nil {
		return fmt.Errorf("discard local changes: %w", err)
	}
	g.forgetWritten()
	return g.reloadMetaAndCheck()
}

func (g *GitStore) entryTimes(rel string) (time.Time, time.Time, string, error) {
	out, err := g.git.Run("log", "-1", "--format=%cI%x1f%an", "--", rel)
	if err != nil {
		return time.Time{}, time.Time{}, "", err
	}
	fields := strings.SplitN(strings.TrimSpace(out), "\x1f", entryFieldParts)
	if len(fields) != entryFieldParts {
		return time.Time{}, time.Time{}, "", fmt.Errorf("parse git log output for %s", rel)
	}
	updated, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		return time.Time{}, time.Time{}, "", err
	}
	author := fields[1]
	created := updated
	out, err = g.git.Run("log", "--diff-filter=A", "--format=%cI", "--", rel)
	if err == nil {
		first := ""
		for line := range strings.SplitSeq(out, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				first = line
			}
		}
		if first != "" {
			if ts, terr := time.Parse(time.RFC3339, first); terr == nil {
				created = ts
			}
		}
	}
	return created, updated, author, nil
}

func (g *GitStore) mutate(msg string, op func() error) error {
	return g.ExecTxMsg(context.Background(), msg, op)
}

func (g *GitStore) commit(msg string) error {
	g.mu.Lock()
	dirty := g.dirty
	g.mu.Unlock()
	if !dirty {
		return nil
	}
	_, err := g.git.Run("commit", "-m", msg)
	if err != nil {
		if strings.Contains(err.Error(), "nothing to commit") {
			g.mu.Lock()
			g.dirty = false
			g.mu.Unlock()
			return nil
		}
		return fmt.Errorf("git commit: %w", err)
	}
	g.mu.Lock()
	g.dirty = false
	g.mu.Unlock()
	return nil
}

func (g *GitStore) markDirty() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.dirty = true
}

func (g *GitStore) ExecTx(fn func() error) error {
	return g.ExecTxMsg(context.Background(), "psst: batch", fn)
}

func (g *GitStore) ExecTxMsg(_ context.Context, msg string, fn func() error) error {
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
	defer func() { _ = lock.Unlock() }()
	if err = g.pullForWrite(); err != nil {
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
	if err = fn(); err != nil {
		return err
	}
	if err = g.commit(msg); err != nil {
		return err
	}
	if err = g.push(); err != nil && !errors.Is(err, ErrNoRemote) {
		return err
	}
	return nil
}

func (g *GitStore) RotateSalt(_ context.Context, saltB64 string) error {
	g.mu.Lock()
	inTx := g.txDepth > 0
	g.mu.Unlock()
	if !inTx {
		return errors.New("rotate salt must run inside a transaction")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	if len(salt) < saltSize {
		return errors.New("salt must be at least 16 bytes")
	}
	g.mu.Lock()
	if g.meta == nil {
		mErr := g.metaErr
		g.mu.Unlock()
		if mErr != nil {
			return fmt.Errorf("vault metadata missing or invalid: %w", mErr)
		}
		return errors.New("vault metadata missing or invalid")
	}
	g.meta.SaltB64 = saltB64
	encoded := g.meta.Encode()
	g.mu.Unlock()
	if err = os.WriteFile(filepath.Join(g.repoDir, "psst.yaml"), encoded, 0o600); err != nil {
		return fmt.Errorf("write vault metadata: %w", err)
	}
	if _, err = g.git.Run("add", "psst.yaml"); err != nil {
		return fmt.Errorf("git add psst.yaml: %w", err)
	}
	g.markDirty()
	return nil
}

func (g *GitStore) SyncAcceptRotation(_ context.Context) (*VaultMeta, error) {
	lock, err := LockRepo(g.repoDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.Unlock() }()
	if _, pullErr := g.git.Run("pull", "--rebase", "--autostash"); pullErr != nil {
		_, _ = g.git.Run("rebase", "--abort")
		msg := pullErr.Error()
		if strings.Contains(msg, "CONFLICT") || strings.Contains(msg, "could not apply") ||
			strings.Contains(msg, "Rebase") {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("pull failed: %w", pullErr)
	}
	data, err := os.ReadFile(filepath.Join(g.repoDir, "psst.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read vault metadata: %w", err)
	}
	newMeta, err := ParseVaultMeta(data)
	if err != nil {
		return nil, fmt.Errorf("invalid vault metadata: %w", err)
	}
	if g.opts.LoadPins != nil {
		if pin := g.opts.LoadPins(); pin != nil {
			if newMeta.SaltB64 == pin.SaltB64 {
				if pinErr := CheckPinned(newMeta, pin); pinErr != nil {
					return nil, fmt.Errorf("vault KDF parameters: %w", pinErr)
				}
			} else {
				p, m := pin.Params, newMeta.Params
				if m.Time < p.Time || m.Memory < p.Memory || m.Threads < p.Threads {
					return nil, fmt.Errorf("rotation weakens KDF parameters: %w", ErrKDFWeakened)
				}
			}
		}
	}
	g.mu.Lock()
	g.meta = newMeta
	g.mu.Unlock()
	return newMeta, nil
}

func (g *GitStore) AheadOfUpstream(_ context.Context) bool {
	out, err := g.git.Run("status", "-sb")
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(out, "\n")
	return strings.Contains(first, "[ahead")
}

func (g *GitStore) SetSecret(_ context.Context, name string, encValue, iv []byte, tags []string) error {
	tag := ""
	switch len(tags) {
	case 0:
	case 1:
		tag = tags[0]
		if !ValidTag.MatchString(tag) {
			return fmt.Errorf("invalid tag %q", tag)
		}
	default:
		return errors.New("git vault supports a single tag")
	}
	oldPath, oldTag, had := g.locate(name)
	path, pathErr := SecretPath(g.secretsRoot(), name, tag)
	if pathErr != nil {
		return pathErr
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
		if _, err = g.git.Run("add", rel); err != nil {
			return fmt.Errorf("git add %s: %w", rel, err)
		}
		g.recordWritten(rel)
		if had && oldPath != path {
			if rmErr := os.Remove(oldPath); rmErr != nil && !os.IsNotExist(rmErr) {
				return fmt.Errorf("remove old secret: %w", rmErr)
			}
			oldRel, relErr := filepath.Rel(g.repoDir, oldPath)
			if relErr != nil {
				return fmt.Errorf("old secret path: %w", relErr)
			}
			if _, addErr := g.git.Run("add", oldRel); addErr != nil {
				return fmt.Errorf("git add %s: %w", oldRel, addErr)
			}
			g.recordWritten(oldRel)
		}
		g.markDirty()
		return nil
	})
}

func (g *GitStore) GetSecret(_ context.Context, name string) (*StoredSecret, error) {
	diverged, err := g.SyncPullRead()
	if err != nil {
		return nil, err
	}
	path, tag, ok := g.locate(name)
	if !ok {
		return nil, nil //nolint:nilnil // not-found is not an error
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
	created, updated := time.Time{}, time.Time{}
	if rel, relErr := filepath.Rel(g.repoDir, path); relErr == nil {
		created, updated, _, _ = g.entryTimes(rel)
	}
	if diverged {
		fmt.Fprintln(os.Stderr, "psst: warning: local clone has unpushed changes; run psst sync")
	}
	return &StoredSecret{
		Name:           name,
		EncryptedValue: ct,
		IV:             iv,
		Tags:           secretTags,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}, nil
}

func (g *GitStore) GetAllSecrets(_ context.Context) ([]StoredSecret, error) {
	if _, err := g.SyncPullRead(); err != nil {
		return nil, err
	}
	entries, err := g.walkSecrets()
	if err != nil {
		return nil, err
	}
	result := make([]StoredSecret, 0, len(entries))
	for _, e := range entries {
		data, readErr := os.ReadFile(e.path)
		if readErr != nil {
			return nil, fmt.Errorf("read secret %q: %w", e.name, readErr)
		}
		ct, iv, decErr := DecodeSecretFile(data)
		if decErr != nil {
			return nil, fmt.Errorf("decode secret file %s: %w", e.path, decErr)
		}
		var secretTags []string
		if e.tag != "" {
			secretTags = []string{e.tag}
		}
		result = append(result, StoredSecret{Name: e.name, EncryptedValue: ct, IV: iv, Tags: secretTags})
	}
	return result, nil
}

func (g *GitStore) ListSecrets(_ context.Context) ([]SecretMeta, error) {
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
		created, updated, author := time.Time{}, time.Time{}, ""
		if rel, relErr := filepath.Rel(g.repoDir, e.path); relErr == nil {
			created, updated, author, _ = g.entryTimes(rel)
		}
		result = append(
			result,
			SecretMeta{Name: e.name, Tags: secretTags, CreatedAt: created, UpdatedAt: updated, UpdatedBy: author},
		)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (g *GitStore) DeleteSecret(_ context.Context, name string) error {
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
		if _, err = g.git.Run("add", rel); err != nil {
			return fmt.Errorf("git add %s: %w", rel, err)
		}
		g.recordWritten(rel)
		g.markDirty()
		return nil
	})
}

func (g *GitStore) GetHistory(_ context.Context, name string) ([]HistoryEntry, error) {
	if !ValidSecretName.MatchString(name) {
		return nil, nil
	}
	if _, err := g.SyncPullRead(); err != nil {
		return nil, err
	}
	path, _, ok := g.locate(name)
	if !ok {
		return nil, nil
	}
	rel, err := filepath.Rel(g.repoDir, path)
	if err != nil {
		return nil, fmt.Errorf("secret path: %w", err)
	}
	rel = filepath.ToSlash(rel)
	out, err := g.git.Run("log", "--follow", "--format=%H%x1f%cI%x1f%an", "--name-only", "--", rel)
	if err != nil {
		return nil, fmt.Errorf("git log: %w", err)
	}
	type histCommit struct {
		hash, date, author, path string
	}
	var commits []histCommit
	cur := -1
	for line := range strings.SplitSeq(out, "\n") {
		if line == "" {
			continue
		}
		if strings.ContainsRune(line, '\x1f') {
			parts := strings.Split(line, "\x1f")
			if len(parts) != commitFieldParts {
				continue
			}
			commits = append(commits, histCommit{hash: parts[0], date: parts[1], author: parts[2]})
			cur = len(commits) - 1
			continue
		}
		if cur >= 0 && commits[cur].path == "" {
			commits[cur].path = strings.TrimSpace(line)
		}
	}
	if len(commits) <= 1 {
		return nil, nil
	}
	commits = commits[1:]
	result := make([]HistoryEntry, 0, len(commits))
	n := len(commits)
	for i, c := range commits {
		if c.path == "" {
			c.path = rel
		}
		blob, showErr := g.git.Run("show", c.hash+":"+c.path)
		if showErr != nil {
			return nil, fmt.Errorf("git show %s: %w", c.path, showErr)
		}
		ct, iv, decErr := DecodeSecretFile([]byte(blob))
		if decErr != nil {
			return nil, fmt.Errorf("decode secret %q: %w", name, decErr)
		}
		ts, terr := time.Parse(time.RFC3339, c.date)
		if terr != nil {
			ts = time.Time{}
		}
		var tags []string
		dir := filepath.Dir(c.path)
		if dir != "." && dir != "secrets" && !strings.Contains(dir, "/") && ValidTag.MatchString(dir) {
			tags = []string{dir}
		}
		result = append(result, HistoryEntry{
			ID: 0, Name: name, Version: n - i,
			EncryptedValue: ct, IV: iv, Tags: tags,
			Author: c.author, ArchivedAt: ts,
		})
	}
	return result, nil
}

func (g *GitStore) AddHistory(_ context.Context, _ string, _ int, _, _ []byte, _ []string) error {
	return nil
}

func (g *GitStore) PruneHistory(_ context.Context, _ string, _ int) error {
	return nil
}

func (g *GitStore) DeleteHistory(_ context.Context, _ string) error {
	return nil
}

func (g *GitStore) Close() error {
	return nil
}

func (g *GitStore) GetMeta(_ context.Context, key string) (string, error) {
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
	case metaKeyKDFTime:
		if g.meta == nil {
			return "", g.metaErr
		}
		return strconv.FormatUint(uint64(g.meta.Params.Time), 10), nil
	case metaKeyKDFMemory:
		if g.meta == nil {
			return "", g.metaErr
		}
		return strconv.FormatUint(uint64(g.meta.Params.Memory), 10), nil
	case metaKeyKDFThreads:
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

func (g *GitStore) SetMeta(_ context.Context, key, value string) error {
	switch key {
	case metaKeyKDFTime, metaKeyKDFMemory, metaKeyKDFThreads:
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
		return errors.New("vault metadata missing or invalid")
	}
	bits := 32
	if key == metaKeyKDFThreads {
		bits = 8
	}
	n, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		g.mu.Unlock()
		return fmt.Errorf("invalid %s value %q: %w", key, value, err)
	}
	switch key {
	case metaKeyKDFTime:
		g.meta.Params.Time = uint32(n) //nolint:gosec // n is parsed with bits=32 above
	case metaKeyKDFMemory:
		g.meta.Params.Memory = uint32(n) //nolint:gosec // n is parsed with bits=32 above
	case metaKeyKDFThreads:
		g.meta.Params.Threads = uint8(n) //nolint:gosec // n is parsed with bits=8 above
	}
	encoded := g.meta.Encode()
	g.mu.Unlock()
	return g.mutate("psst: migrate", func() error {
		metaPath := filepath.Join(g.repoDir, "psst.yaml")
		if writeErr := os.WriteFile(metaPath, encoded, 0o600); writeErr != nil {
			return fmt.Errorf("write vault metadata: %w", writeErr)
		}
		if _, addErr := g.git.Run("add", "psst.yaml"); addErr != nil {
			return fmt.Errorf("git add psst.yaml: %w", addErr)
		}
		g.markDirty()
		return nil
	})
}

func (g *GitStore) IncrementMetaInt(ctx context.Context, key string, increment int) (int, error) {
	cur, err := g.GetMeta(ctx, key)
	if err != nil {
		return 0, err
	}
	n := 0
	if cur != "" {
		n, err = strconv.Atoi(cur)
		if err != nil {
			return 0, fmt.Errorf("increment meta %q: invalid integer %q: %w", key, cur, err)
		}
	}
	n += increment
	if err = g.SetMeta(ctx, key, strconv.Itoa(n)); err != nil {
		return 0, err
	}
	return n, nil
}

var _ SecretStore = (*GitStore)(nil)

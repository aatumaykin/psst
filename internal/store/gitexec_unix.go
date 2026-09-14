//go:build !windows

package store

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

type RepoLock struct {
	path string
	f    *os.File
}

func LockRepo(repoDir string) (*RepoLock, error) {
	return LockRepoWait(repoDir, lockWait)
}

func LockRepoWait(repoDir string, wait time.Duration) (*RepoLock, error) {
	path := repoDir + "/.psst.lock"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, gitCfgFilePerm)
	if err != nil {
		return nil, fmt.Errorf("open repo lock: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		fd := int(f.Fd()) //nolint:gosec // fd fits int on supported platforms
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &RepoLock{path: path, f: f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("flock repo: %w", err)
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, errors.New("repo is locked by another psst process")
		}
		time.Sleep(lockRetryInterval)
	}
}

func (l *RepoLock) Unlock() error {
	fd := int(l.f.Fd()) //nolint:gosec // fd fits int on supported platforms
	if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
		_ = l.f.Close()
		return fmt.Errorf("unlock repo: %w", err)
	}
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("close repo lock: %w", err)
	}
	return nil
}

//go:build windows

package store

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
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
		err = lockHandle(f)
		if err == nil {
			return &RepoLock{path: path, f: f}, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			_ = f.Close()
			return nil, fmt.Errorf("lock repo: %w", err)
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, errors.New("repo is locked by another psst process")
		}
		time.Sleep(lockRetryInterval)
	}
}

func lockHandle(f *os.File) error {
	handle := windows.Handle(f.Fd())
	var ovl windows.Overlapped
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	if err := windows.LockFileEx(handle, flags, 0, 1, 0, &ovl); err != nil {
		return err
	}
	return nil
}

func (l *RepoLock) Unlock() error {
	handle := windows.Handle(l.f.Fd())
	var ovl windows.Overlapped
	if err := windows.UnlockFileEx(handle, 0, 1, 0, &ovl); err != nil {
		_ = l.f.Close()
		return fmt.Errorf("unlock repo: %w", err)
	}
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("close repo lock: %w", err)
	}
	return nil
}

package store

import (
	"context"
	"time"
)

// StoredSecret is an encrypted secret as stored in the database.
type StoredSecret struct {
	Name           string
	EncryptedValue []byte
	IV             []byte
	Tags           []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// SecretMeta is secret metadata without encrypted values.
type SecretMeta struct {
	Name      string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// HistoryEntry is a previous version of a stored secret.
type HistoryEntry struct {
	ID             int64
	Name           string
	Version        int
	EncryptedValue []byte
	IV             []byte
	Tags           []string
	ArchivedAt     time.Time
}

// SecretStore is the persistence interface for encrypted secrets.
type SecretStore interface {
	InitSchema() error
	GetSecret(ctx context.Context, name string) (*StoredSecret, error)
	GetAllSecrets(ctx context.Context) ([]StoredSecret, error)
	SetSecret(ctx context.Context, name string, encValue, iv []byte, tags []string) error
	DeleteSecret(ctx context.Context, name string) error
	DeleteHistory(ctx context.Context, name string) error
	ListSecrets(ctx context.Context) ([]SecretMeta, error)
	GetHistory(ctx context.Context, name string) ([]HistoryEntry, error)
	AddHistory(ctx context.Context, name string, version int, encValue, iv []byte, tags []string) error
	PruneHistory(ctx context.Context, name string, keepVersions int) error
	ExecTx(fn func() error) error
	GetMeta(ctx context.Context, key string) (string, error)
	SetMeta(ctx context.Context, key, value string) error
	IncrementMetaInt(ctx context.Context, key string, increment int) (int, error)
	Close() error
}

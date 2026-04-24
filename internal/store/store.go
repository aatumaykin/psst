package store

import "time"

type StoredSecret struct {
	Name           string
	EncryptedValue []byte
	IV             []byte
	Tags           []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type SecretMeta struct {
	Name      string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type HistoryEntry struct {
	ID             int64
	Name           string
	Version        int
	EncryptedValue []byte
	IV             []byte
	Tags           []string
	ArchivedAt     time.Time
}

type SecretStore interface {
	InitSchema() error
	GetSecret(name string) (*StoredSecret, error)
	GetAllSecrets() ([]StoredSecret, error)
	SetSecret(name string, encValue, iv []byte, tags []string) error
	DeleteSecret(name string) error
	DeleteHistory(name string) error
	ListSecrets() ([]SecretMeta, error)
	GetHistory(name string) ([]HistoryEntry, error)
	AddHistory(name string, version int, encValue, iv []byte, tags []string) error
	PruneHistory(name string, keepVersions int) error
	ExecTx(fn func() error) error
	Close() error
}

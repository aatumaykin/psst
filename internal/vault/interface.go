package vault

import "context"

type SecretReader interface {
	GetSecret(ctx context.Context, name string) (*Secret, error)
	GetAllSecrets(ctx context.Context) (map[string][]byte, error)
	ListSecrets(ctx context.Context) ([]SecretMeta, error)
}

type SecretWriter interface {
	SetSecret(ctx context.Context, name string, value []byte, tags []string) error
	DeleteSecret(ctx context.Context, name string) error
}

type HistoryManager interface {
	GetHistory(ctx context.Context, name string) ([]SecretHistoryEntry, error)
	Rollback(ctx context.Context, name string, version int) error
}

type TagManager interface {
	AddTag(ctx context.Context, name, tag string) error
	RemoveTag(ctx context.Context, name, tag string) error
	GetSecretsByTags(ctx context.Context, tags []string) ([]SecretMeta, error)
	GetSecretNamesByTags(ctx context.Context, tags []string) ([]string, error)
	GetSecretsByTagValues(ctx context.Context, tags []string) (map[string][]byte, error)
}

type Lifecycle interface {
	Unlock(ctx context.Context) error
	MigrateKDF(ctx context.Context) error
	Close() error
}

type Interface interface {
	SecretReader
	SecretWriter
	HistoryManager
	TagManager
	Lifecycle
}

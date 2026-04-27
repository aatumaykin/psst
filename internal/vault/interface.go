package vault

import "context"

type VaultInterface interface {
	Unlock(ctx context.Context) error
	GetSecret(ctx context.Context, name string) (*Secret, error)
	SetSecret(ctx context.Context, name string, value []byte, tags []string) error
	ListSecrets(ctx context.Context) ([]SecretMeta, error)
	DeleteSecret(ctx context.Context, name string) error
	GetAllSecrets(ctx context.Context) (map[string][]byte, error)
	GetHistory(ctx context.Context, name string) ([]SecretHistoryEntry, error)
	Rollback(ctx context.Context, name string, version int) error
	AddTag(ctx context.Context, name, tag string) error
	RemoveTag(ctx context.Context, name, tag string) error
	GetSecretsByTags(ctx context.Context, tags []string) ([]SecretMeta, error)
	GetSecretNamesByTags(ctx context.Context, tags []string) ([]string, error)
	GetSecretsByTagValues(ctx context.Context, tags []string) (map[string][]byte, error)
	MigrateKDF(ctx context.Context) error
	Close() error
}

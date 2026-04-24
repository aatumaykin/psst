package vault

import (
	"time"

	"github.com/aatumaykin/psst/internal/store"
)

type Secret struct {
	Name      string
	Value     string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SecretMeta = store.SecretMeta

type SecretHistoryEntry struct {
	Version    int
	Tags       []string
	ArchivedAt time.Time
}

type InitOptions struct {
	Global       bool
	Env          string
	SkipKeychain bool
	Key          string
}

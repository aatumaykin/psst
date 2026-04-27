package vault

import (
	"time"
)

// Secret holds a decrypted secret with metadata.
type Secret struct {
	Name      string
	Value     []byte
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SecretMeta is metadata for a stored secret (no decrypted value).
type SecretMeta struct {
	Name      string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SecretHistoryEntry represents a previous version of a secret.
type SecretHistoryEntry struct {
	Version    int
	Tags       []string
	ArchivedAt time.Time
}

// InitOptions configures vault initialization.
type InitOptions struct {
	Global       bool
	Env          string
	SkipKeychain bool
	Key          string
}

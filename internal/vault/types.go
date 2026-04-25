package vault

import (
	"time"
)

type Secret struct {
	Name      string
	Value     []byte
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SecretMeta struct {
	Name      string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

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

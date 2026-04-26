package store

import (
	"context"
	"database/sql"
	"fmt"
)

func initSchema(db *sql.DB) error {
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS secrets (
			name TEXT PRIMARY KEY,
			encrypted_value BLOB NOT NULL,
			iv BLOB NOT NULL,
			created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
			updated_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
			tags TEXT DEFAULT '[]'
		)
	`)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS secrets_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			version INTEGER NOT NULL,
			encrypted_value BLOB NOT NULL,
			iv BLOB NOT NULL,
			tags TEXT DEFAULT '[]',
			archived_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
			UNIQUE(name, version)
		)
	`)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_secrets_history_name ON secrets_history(name)`)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS vault_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return migrateAddTagsColumn(db, "secrets")
}

func migrateAddTagsColumn(db *sql.DB, table string) error {
	ctx := context.Background()
	allowed := map[string]bool{"secrets": true, "secrets_history": true}
	if !allowed[table] {
		return fmt.Errorf("unknown table: %s", table)
	}
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return err
	}
	defer rows.Close()

	hasTags := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dfltValue any
		var pk int
		if scanErr := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); scanErr != nil {
			return scanErr
		}
		if name == "tags" {
			hasTags = true
		}
	}

	if !hasTags {
		q := "ALTER TABLE " + table + " ADD COLUMN tags TEXT DEFAULT '[]'" //nolint:gosec // table validated against allowlist
		if _, alterErr := db.ExecContext(ctx, q); alterErr != nil {
			return alterErr
		}
	}
	return nil
}

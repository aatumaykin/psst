package store

import "database/sql"

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
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

	_, err = db.Exec(`
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

	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_secrets_history_name ON secrets_history(name)`)
	if err != nil {
		return err
	}

	return migrateAddTagsColumn(db, "secrets")
}

func migrateAddTagsColumn(db *sql.DB, table string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer rows.Close()

	hasTags := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dfltValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "tags" {
			hasTags = true
		}
	}

	if !hasTags {
		_, err := db.Exec("ALTER TABLE " + table + " ADD COLUMN tags TEXT DEFAULT '[]'")
		if err != nil {
			return err
		}
	}
	return nil
}

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteStore struct {
	db *sql.DB
	currentTx *sql.Tx
}

func NewSQLite(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	os.Chmod(dbPath, 0600)
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) exec(query string, args ...any) (sql.Result, error) {
	if s.currentTx != nil {
		return s.currentTx.Exec(query, args...)
	}
	return s.db.Exec(query, args...)
}

func (s *SQLiteStore) query(query string, args ...any) (*sql.Rows, error) {
	if s.currentTx != nil {
		return s.currentTx.Query(query, args...)
	}
	return s.db.Query(query, args...)
}

func (s *SQLiteStore) queryRow(query string, args ...any) *sql.Row {
	if s.currentTx != nil {
		return s.currentTx.QueryRow(query, args...)
	}
	return s.db.QueryRow(query, args...)
}

func scanTagsAndTimes(tagsJSON string, createdAt, updatedAt string) (tags []string, created, updated time.Time, err error) {
	if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("parse tags: %w", err)
	}
	created, err = time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("parse created_at: %w", err)
	}
	updated, err = time.Parse("2006-01-02 15:04:05", updatedAt)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return tags, created, updated, nil
}

func scanHistoryTagsAndTime(tagsJSON, archivedAtStr string) (tags []string, archivedAt time.Time, err error) {
	if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
		return nil, time.Time{}, fmt.Errorf("parse tags: %w", err)
	}
	archivedAt, err = time.Parse("2006-01-02 15:04:05", archivedAtStr)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse archived_at: %w", err)
	}
	return tags, archivedAt, nil
}

func (s *SQLiteStore) InitSchema() error {
	return initSchema(s.db)
}

func (s *SQLiteStore) GetSecret(name string) (*StoredSecret, error) {
	row := s.queryRow(
		"SELECT name, encrypted_value, iv, tags, created_at, updated_at FROM secrets WHERE name = ?",
		name,
	)
	var sec StoredSecret
	var tagsJSON string
	var createdAt, updatedAt string
	var err error
	if err = row.Scan(&sec.Name, &sec.EncryptedValue, &sec.IV, &tagsJSON, &createdAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get secret: %w", err)
	}
	sec.Tags, sec.CreatedAt, sec.UpdatedAt, err = scanTagsAndTimes(tagsJSON, createdAt, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse secret metadata: %w", err)
	}
	return &sec, nil
}

func (s *SQLiteStore) GetAllSecrets() ([]StoredSecret, error) {
	rows, err := s.query("SELECT name, encrypted_value, iv, tags, created_at, updated_at FROM secrets ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []StoredSecret
	for rows.Next() {
		var sec StoredSecret
		var tagsJSON string
		var createdAt, updatedAt string
		if err := rows.Scan(&sec.Name, &sec.EncryptedValue, &sec.IV, &tagsJSON, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		sec.Tags, sec.CreatedAt, sec.UpdatedAt, err = scanTagsAndTimes(tagsJSON, createdAt, updatedAt)
		if err != nil {
			return nil, fmt.Errorf("parse secret metadata: %w", err)
		}
		result = append(result, sec)
	}
	return result, nil
}

func (s *SQLiteStore) SetSecret(name string, encValue, iv []byte, tags []string) error {
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	_, err = s.exec(
		`INSERT INTO secrets (name, encrypted_value, iv, tags, updated_at)
		 VALUES (?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%S','now'))
		 ON CONFLICT(name) DO UPDATE SET
		   encrypted_value = excluded.encrypted_value,
		   iv = excluded.iv,
		   tags = excluded.tags,
		   updated_at = excluded.updated_at`,
		name, encValue, iv, string(tagsJSON),
	)
	return err
}

func (s *SQLiteStore) DeleteSecret(name string) error {
	_, err := s.exec("DELETE FROM secrets WHERE name = ?", name)
	return err
}

func (s *SQLiteStore) DeleteHistory(name string) error {
	_, err := s.exec("DELETE FROM secrets_history WHERE name = ?", name)
	return err
}

func (s *SQLiteStore) ListSecrets() ([]SecretMeta, error) {
	rows, err := s.query("SELECT name, tags, created_at, updated_at FROM secrets ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SecretMeta
	for rows.Next() {
		var m SecretMeta
		var tagsJSON string
		var createdAt, updatedAt string
		if err := rows.Scan(&m.Name, &tagsJSON, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		m.Tags, m.CreatedAt, m.UpdatedAt, err = scanTagsAndTimes(tagsJSON, createdAt, updatedAt)
		if err != nil {
			return nil, fmt.Errorf("parse secret metadata: %w", err)
		}
		result = append(result, m)
	}
	return result, nil
}

func (s *SQLiteStore) GetHistory(name string) ([]HistoryEntry, error) {
	rows, err := s.query(
		"SELECT id, name, version, encrypted_value, iv, tags, archived_at FROM secrets_history WHERE name = ? ORDER BY version DESC",
		name,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		var tagsJSON string
		var archivedAt string
		if err := rows.Scan(&e.ID, &e.Name, &e.Version, &e.EncryptedValue, &e.IV, &tagsJSON, &archivedAt); err != nil {
			return nil, err
		}
		e.Tags, e.ArchivedAt, err = scanHistoryTagsAndTime(tagsJSON, archivedAt)
		if err != nil {
			return nil, fmt.Errorf("parse history metadata: %w", err)
		}
		result = append(result, e)
	}
	return result, nil
}

func (s *SQLiteStore) AddHistory(name string, version int, encValue, iv []byte, tags []string) error {
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	_, err = s.exec(
		"INSERT INTO secrets_history (name, version, encrypted_value, iv, tags) VALUES (?, ?, ?, ?, ?)",
		name, version, encValue, iv, string(tagsJSON),
	)
	return err
}

func (s *SQLiteStore) PruneHistory(name string, keepVersions int) error {
	_, err := s.exec(
		`DELETE FROM secrets_history WHERE name = ? AND version <= (
			SELECT MAX(version) - ? FROM secrets_history WHERE name = ?
		)`,
		name, keepVersions, name,
	)
	return err
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) ExecTx(fn func() error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	s.currentTx = tx
	defer func() { s.currentTx = nil }()

	if err := fn(); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetMeta(key string) (string, error) {
	var value string
	err := s.queryRow("SELECT value FROM vault_meta WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *SQLiteStore) SetMeta(key, value string) error {
	_, err := s.exec(`INSERT INTO vault_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLite(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) InitSchema() error {
	return initSchema(s.db)
}

func (s *SQLiteStore) GetSecret(name string) (*StoredSecret, error) {
	row := s.db.QueryRow(
		"SELECT name, encrypted_value, iv, tags, created_at, updated_at FROM secrets WHERE name = ?",
		name,
	)
	var sec StoredSecret
	var tagsJSON string
	var createdAt, updatedAt string
	if err := row.Scan(&sec.Name, &sec.EncryptedValue, &sec.IV, &tagsJSON, &createdAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get secret: %w", err)
	}
	json.Unmarshal([]byte(tagsJSON), &sec.Tags)
	sec.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	sec.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	return &sec, nil
}

func (s *SQLiteStore) SetSecret(name string, encValue, iv []byte, tags []string) error {
	tagsJSON, _ := json.Marshal(tags)
	_, err := s.db.Exec(
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
	_, err := s.db.Exec("DELETE FROM secrets WHERE name = ?", name)
	return err
}

func (s *SQLiteStore) DeleteHistory(name string) error {
	_, err := s.db.Exec("DELETE FROM secrets_history WHERE name = ?", name)
	return err
}

func (s *SQLiteStore) ListSecrets() ([]SecretMeta, error) {
	rows, err := s.db.Query("SELECT name, tags, created_at, updated_at FROM secrets ORDER BY name")
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
		json.Unmarshal([]byte(tagsJSON), &m.Tags)
		m.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		m.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
		result = append(result, m)
	}
	return result, nil
}

func (s *SQLiteStore) GetHistory(name string) ([]HistoryEntry, error) {
	rows, err := s.db.Query(
		"SELECT id, name, version, tags, archived_at FROM secrets_history WHERE name = ? ORDER BY version DESC",
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
		if err := rows.Scan(&e.ID, &e.Name, &e.Version, &tagsJSON, &archivedAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(tagsJSON), &e.Tags)
		e.ArchivedAt, _ = time.Parse("2006-01-02 15:04:05", archivedAt)
		result = append(result, e)
	}
	return result, nil
}

func (s *SQLiteStore) AddHistory(name string, version int, encValue, iv []byte, tags []string) error {
	tagsJSON, _ := json.Marshal(tags)
	_, err := s.db.Exec(
		"INSERT INTO secrets_history (name, version, encrypted_value, iv, tags) VALUES (?, ?, ?, ?, ?)",
		name, version, encValue, iv, string(tagsJSON),
	)
	return err
}

func (s *SQLiteStore) PruneHistory(name string, keepVersions int) error {
	_, err := s.db.Exec(
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

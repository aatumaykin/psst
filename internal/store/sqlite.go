package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // sqlite driver registration
)

type SQLiteStore struct {
	mu        sync.Mutex
	db        *sql.DB
	currentTx atomic.Pointer[sql.Tx]
	dbPath    string
}

func NewSQLite(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second, //nolint:mnd // reasonable connection timeout
	)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("verify database connection: %w", err)
	}
	return &SQLiteStore{db: db, dbPath: dbPath}, nil
}

func (s *SQLiteStore) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if tx := s.currentTx.Load(); tx != nil {
		return tx.ExecContext(ctx, query, args...)
	}
	return s.db.ExecContext(ctx, query, args...)
}

func (s *SQLiteStore) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if tx := s.currentTx.Load(); tx != nil {
		return tx.QueryContext(ctx, query, args...)
	}
	return s.db.QueryContext(ctx, query, args...)
}

func (s *SQLiteStore) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	if tx := s.currentTx.Load(); tx != nil {
		return tx.QueryRowContext(ctx, query, args...)
	}
	return s.db.QueryRowContext(ctx, query, args...)
}

func scanTagsAndTimes(
	tagsJSON string, createdAt, updatedAt string,
) ([]string, time.Time, time.Time, error) {
	var tags []string
	if unmarshalErr := json.Unmarshal([]byte(tagsJSON), &tags); unmarshalErr != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("parse tags: %w", unmarshalErr)
	}
	created, err := time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("parse created_at: %w", err)
	}
	updated, err := time.Parse("2006-01-02 15:04:05", updatedAt)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return tags, created, updated, nil
}

func scanHistoryTagsAndTime(tagsJSON, archivedAtStr string) ([]string, time.Time, error) {
	var tags []string
	if unmarshalErr := json.Unmarshal([]byte(tagsJSON), &tags); unmarshalErr != nil {
		return nil, time.Time{}, fmt.Errorf("parse tags: %w", unmarshalErr)
	}
	archivedAt, err := time.Parse("2006-01-02 15:04:05", archivedAtStr)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse archived_at: %w", err)
	}
	return tags, archivedAt, nil
}

func (s *SQLiteStore) InitSchema() error {
	if err := initSchema(s.db); err != nil {
		return err
	}
	if s.dbPath != "" {
		if chmodErr := os.Chmod(s.dbPath, 0600); chmodErr != nil {
			return chmodErr
		}
		_ = os.Chmod(s.dbPath+"-wal", 0600)
		_ = os.Chmod(s.dbPath+"-shm", 0600)
	}
	return nil
}

func (s *SQLiteStore) GetSecret(ctx context.Context, name string) (*StoredSecret, error) {
	row := s.queryRow(ctx,
		"SELECT name, encrypted_value, iv, tags, created_at, updated_at FROM secrets WHERE name = ?",
		name,
	)
	var sec StoredSecret
	var tagsJSON string
	var createdAt, updatedAt string
	if scanErr := row.Scan(&sec.Name, &sec.EncryptedValue, &sec.IV, &tagsJSON, &createdAt, &updatedAt); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // not-found is not an error
		}
		return nil, fmt.Errorf("get secret: %w", scanErr)
	}
	tags, created, updated, err := scanTagsAndTimes(tagsJSON, createdAt, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse secret metadata: %w", err)
	}
	sec.Tags = tags
	sec.CreatedAt = created
	sec.UpdatedAt = updated
	return &sec, nil
}

func (s *SQLiteStore) GetAllSecrets(ctx context.Context) ([]StoredSecret, error) {
	rows, err := s.query(
		ctx,
		"SELECT name, encrypted_value, iv, tags, created_at, updated_at FROM secrets ORDER BY name",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []StoredSecret
	for rows.Next() {
		var sec StoredSecret
		var tagsJSON string
		var createdAt, updatedAt string
		scanErr := rows.Scan(
			&sec.Name, &sec.EncryptedValue, &sec.IV,
			&tagsJSON, &createdAt, &updatedAt,
		)
		if scanErr != nil {
			return nil, scanErr
		}
		tags, created, updated, scanErr := scanTagsAndTimes(tagsJSON, createdAt, updatedAt)
		if scanErr != nil {
			return nil, fmt.Errorf("parse secret metadata: %w", scanErr)
		}
		sec.Tags = tags
		sec.CreatedAt = created
		sec.UpdatedAt = updated
		result = append(result, sec)
	}
	if err2 := rows.Err(); err2 != nil {
		return nil, err2
	}
	return result, nil
}

func (s *SQLiteStore) SetSecret(ctx context.Context, name string, encValue, iv []byte, tags []string) error {
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	_, err = s.exec(ctx,
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

func (s *SQLiteStore) DeleteSecret(ctx context.Context, name string) error {
	_, err := s.exec(ctx, "DELETE FROM secrets WHERE name = ?", name)
	return err
}

func (s *SQLiteStore) DeleteHistory(ctx context.Context, name string) error {
	_, err := s.exec(ctx, "DELETE FROM secrets_history WHERE name = ?", name)
	return err
}

func (s *SQLiteStore) ListSecrets(ctx context.Context) ([]SecretMeta, error) {
	rows, err := s.query(ctx, "SELECT name, tags, created_at, updated_at FROM secrets ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SecretMeta
	for rows.Next() {
		var m SecretMeta
		var tagsJSON string
		var createdAt, updatedAt string
		if scanErr := rows.Scan(&m.Name, &tagsJSON, &createdAt, &updatedAt); scanErr != nil {
			return nil, scanErr
		}
		tags, created, updated, scanErr := scanTagsAndTimes(tagsJSON, createdAt, updatedAt)
		if scanErr != nil {
			return nil, fmt.Errorf("parse secret metadata: %w", scanErr)
		}
		m.Tags = tags
		m.CreatedAt = created
		m.UpdatedAt = updated
		result = append(result, m)
	}
	if err2 := rows.Err(); err2 != nil {
		return nil, err2
	}
	return result, nil
}

func (s *SQLiteStore) GetHistory(ctx context.Context, name string) ([]HistoryEntry, error) {
	rows, err := s.query(
		ctx,
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
		scanErr := rows.Scan(
			&e.ID, &e.Name, &e.Version,
			&e.EncryptedValue, &e.IV, &tagsJSON, &archivedAt,
		)
		if scanErr != nil {
			return nil, scanErr
		}
		tags, archived, scanErr := scanHistoryTagsAndTime(tagsJSON, archivedAt)
		if scanErr != nil {
			return nil, fmt.Errorf("parse history metadata: %w", scanErr)
		}
		e.Tags = tags
		e.ArchivedAt = archived
		result = append(result, e)
	}
	if err2 := rows.Err(); err2 != nil {
		return nil, err2
	}
	return result, nil
}

func (s *SQLiteStore) AddHistory(
	ctx context.Context,
	name string,
	version int,
	encValue, iv []byte,
	tags []string,
) error {
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	_, err = s.exec(ctx,
		"INSERT INTO secrets_history (name, version, encrypted_value, iv, tags) VALUES (?, ?, ?, ?, ?)",
		name, version, encValue, iv, string(tagsJSON),
	)
	return err
}

func (s *SQLiteStore) PruneHistory(ctx context.Context, name string, keepVersions int) error {
	_, err := s.exec(ctx,
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
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	s.currentTx.Store(tx)
	defer func() {
		s.currentTx.Store(nil)
		_ = tx.Rollback()
	}()

	if fnErr := fn(); fnErr != nil {
		return fnErr
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetMeta(ctx context.Context, key string) (string, error) {
	var value string
	err := s.queryRow(ctx, "SELECT value FROM vault_meta WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *SQLiteStore) SetMeta(ctx context.Context, key, value string) error {
	q := `INSERT INTO vault_meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	_, err := s.exec(ctx, q, key, value)
	return err
}

func (s *SQLiteStore) IncrementMetaInt(ctx context.Context, key string, increment int) (int, error) {
	q := `INSERT INTO vault_meta (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT)`
	_, err := s.exec(ctx, q, key, strconv.Itoa(increment), increment)
	if err != nil {
		return 0, err
	}
	val, err := s.GetMeta(ctx, key)
	if err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(val)
	return n, nil
}

package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/aefw/hapm/internal/domain"
)

// SettingRepository adalah implementasi SQLite untuk domain.SettingRepository
type SettingRepository struct{ db *sql.DB }

func NewSettingRepository(db *sql.DB) *SettingRepository {
	return &SettingRepository{db: db}
}

func (r *SettingRepository) Get(ctx context.Context, key string) (*domain.Setting, error) {
	q := `SELECT key, value, encrypted, created, timestamp FROM settings WHERE key=? LIMIT 1`
	var s domain.Setting
	var encrypted int
	err := r.db.QueryRowContext(ctx, q, key).Scan(
		&s.Key, &s.Value, &encrypted, &s.Created, &s.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("setting tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("setting get: %w", err)
	}
	s.Encrypted = encrypted == 1
	return &s, nil
}

func (r *SettingRepository) Set(ctx context.Context, key, value string, encrypted bool) error {
	q := `INSERT INTO settings (key, value, encrypted, timestamp)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value=excluded.value,
			encrypted=excluded.encrypted,
			timestamp=excluded.timestamp`
	_, err := r.db.ExecContext(ctx, q, key, value, boolToInt(encrypted), time.Now())
	if err != nil {
		return fmt.Errorf("setting set: %w", err)
	}
	return nil
}

func (r *SettingRepository) Delete(ctx context.Context, key string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM settings WHERE key=?", key)
	return err
}

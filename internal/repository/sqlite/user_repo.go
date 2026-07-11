package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
)

// UserRepository adalah implementasi SQLite untuk domain.UserRepository
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository membuat instance UserRepository
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) FindByID(ctx context.Context, id int) (*domain.User, error) {
	q := `SELECT id_users, username, email, password, full_name, role,
	             active, locked, lock_until, last_login, created, timestamp
	      FROM users WHERE id_users = ? LIMIT 1`
	row := r.db.QueryRowContext(ctx, q, id)
	return scanUser(row)
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	q := `SELECT id_users, username, email, password, full_name, role,
	             active, locked, lock_until, last_login, created, timestamp
	      FROM users WHERE username = ? LIMIT 1`
	row := r.db.QueryRowContext(ctx, q, username)
	return scanUser(row)
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	q := `SELECT id_users, username, email, password, full_name, role,
	             active, locked, lock_until, last_login, created, timestamp
	      FROM users WHERE email = ? LIMIT 1`
	row := r.db.QueryRowContext(ctx, q, email)
	return scanUser(row)
}

func (r *UserRepository) List(ctx context.Context, f domain.ListFilter) ([]*domain.User, int, error) {
	base := `FROM users`
	var args []interface{}

	if f.Q != "" {
		like := "%" + f.Q + "%"
		base += ` WHERE (username LIKE ? OR email LIKE ? OR full_name LIKE ? OR role LIKE ?)`
		args = append(args, like, like, like, like)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("user list count: %v", err)
	}

	q := `SELECT id_users, username, email, password, full_name, role,
	             active, locked, lock_until, last_login, created, timestamp ` + base + ` ORDER BY created DESC`
	qArgs := append([]interface{}{}, args...)
	if f.Limit > 0 {
		q += " LIMIT ? OFFSET ?"
		qArgs = append(qArgs, f.Limit, f.Start)
	}

	rows, err := r.db.QueryContext(ctx, q, qArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("user list query: %v", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (r *UserRepository) Create(ctx context.Context, u *domain.User) (int, error) {
	q := `INSERT INTO users (username, email, password, full_name, role, active)
	      VALUES (?, ?, ?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q,
		u.Username, u.Email, u.Password, u.FullName, u.Role, boolToInt(u.Active))
	if err != nil {
		return 0, fmt.Errorf("user create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *UserRepository) Update(ctx context.Context, u *domain.User) error {
	q := `UPDATE users SET email=?, full_name=?, role=?, active=?, timestamp=CURRENT_TIMESTAMP
	      WHERE id_users=?`
	_, err := r.db.ExecContext(ctx, q,
		u.Email, u.FullName, u.Role, boolToInt(u.Active), u.ID)
	if err != nil {
		return fmt.Errorf("user update: %v", err)
	}
	return nil
}

func (r *UserRepository) UpdatePassword(ctx context.Context, userID int, passwordHash string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET password=?, timestamp=CURRENT_TIMESTAMP WHERE id_users=?",
		passwordHash, userID)
	if err != nil {
		return fmt.Errorf("user update password: %v", err)
	}
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM users WHERE id_users=?", id)
	return err
}

func (r *UserRepository) UpdateLastLogin(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET last_login=CURRENT_TIMESTAMP, timestamp=CURRENT_TIMESTAMP WHERE id_users=?", id)
	return err
}

func (r *UserRepository) SetLocked(ctx context.Context, id int, locked bool, lockUntil any) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET locked=?, lock_until=?, timestamp=CURRENT_TIMESTAMP WHERE id_users=?",
		boolToInt(locked), lockUntil, id)
	return err
}

// ─── helpers ──────────────────────────────────────────────────────────────────

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanUser(s scanner) (*domain.User, error) {
	var u domain.User
	var lockUntil, lastLogin sql.NullTime
	var active, locked int
	err := s.Scan(
		&u.ID, &u.Username, &u.Email, &u.Password, &u.FullName, &u.Role,
		&active, &locked, &lockUntil, &lastLogin, &u.Created, &u.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %v", err)
	}
	u.Active = active == 1
	u.Locked = locked == 1
	if lockUntil.Valid {
		t := lockUntil.Time
		u.LockUntil = &t
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		u.LastLogin = &t
	}
	return &u, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ─── RefreshTokenRepository ────────────────────────────────────────────────────

type RefreshTokenRepository struct{ db *sql.DB }

func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, rt *domain.RefreshToken) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id_users, token_hash, expires_at) VALUES (?, ?, ?)`,
		rt.UserID, rt.TokenHash, rt.ExpiresAt)
	return err
}

func (r *RefreshTokenRepository) FindByTokenHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	rt := &domain.RefreshToken{}
	var revoked int
	err := r.db.QueryRowContext(ctx,
		`SELECT id_refresh_tokens, id_users, token_hash, expires_at, revoked, created
		 FROM refresh_tokens WHERE token_hash=? LIMIT 1`, hash,
	).Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt, &revoked, &rt.Created)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("refresh token tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan refresh token: %v", err)
	}
	rt.Revoked = revoked == 1
	return rt, nil
}

func (r *RefreshTokenRepository) Revoke(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE refresh_tokens SET revoked=1, timestamp=CURRENT_TIMESTAMP WHERE id_refresh_tokens=?", id)
	return err
}

func (r *RefreshTokenRepository) RevokeAllByUser(ctx context.Context, userID int) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE refresh_tokens SET revoked=1, timestamp=CURRENT_TIMESTAMP WHERE id_users=?", userID)
	return err
}

func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP OR revoked=1")
	return err
}

// ─── LoginAttemptRepository ────────────────────────────────────────────────────

type LoginAttemptRepository struct{ db *sql.DB }

func NewLoginAttemptRepository(db *sql.DB) *LoginAttemptRepository {
	return &LoginAttemptRepository{db: db}
}

func (r *LoginAttemptRepository) Create(ctx context.Context, la *domain.LoginAttempt) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO login_attempts (ip_address, username, success) VALUES (?, ?, ?)`,
		la.IPAddress, la.Username, boolToInt(la.Success))
	return err
}

func (r *LoginAttemptRepository) CountFailedByIP(ctx context.Context, ip string, windowMinutes int) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM login_attempts
		 WHERE ip_address=? AND success=0
		   AND created >= datetime('now', ? || ' minutes')`,
		ip, fmt.Sprintf("-%d", windowMinutes),
	).Scan(&count)
	return count, err
}

func (r *LoginAttemptRepository) CountFailedByUsername(ctx context.Context, username string, windowMinutes int) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM login_attempts
		 WHERE username=? AND success=0
		   AND created >= datetime('now', ? || ' minutes')`,
		username, fmt.Sprintf("-%d", windowMinutes),
	).Scan(&count)
	return count, err
}

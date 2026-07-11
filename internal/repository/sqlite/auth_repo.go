package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
)

// ─── AuthUserRepository ───────────────────────────────────────────────────────

type AuthUserRepository struct{ db *sql.DB }

func NewAuthUserRepository(db *sql.DB) *AuthUserRepository {
	return &AuthUserRepository{db: db}
}

func (r *AuthUserRepository) FindByID(ctx context.Context, id int) (*domain.AuthUser, error) {
	q := `SELECT id_auth_users, username, password_hash, description, enabled, created, timestamp
	      FROM auth_users WHERE id_auth_users=? LIMIT 1`
	return scanAuthUser(r.db.QueryRowContext(ctx, q, id))
}

func (r *AuthUserRepository) FindByUsername(ctx context.Context, username string) (*domain.AuthUser, error) {
	q := `SELECT id_auth_users, username, password_hash, description, enabled, created, timestamp
	      FROM auth_users WHERE username=? LIMIT 1`
	return scanAuthUser(r.db.QueryRowContext(ctx, q, username))
}

func (r *AuthUserRepository) List(ctx context.Context, f domain.ListFilter) ([]*domain.AuthUser, int, error) {
	base := `FROM auth_users`
	var args []interface{}

	if f.Q != "" {
		like := "%" + f.Q + "%"
		base += ` WHERE (username LIKE ? OR description LIKE ?)`
		args = append(args, like, like)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("auth_user list count: %v", err)
	}

	q := `SELECT id_auth_users, username, password_hash, description, enabled, created, timestamp ` + base + ` ORDER BY username ASC`
	qArgs := append([]interface{}{}, args...)
	if f.Limit > 0 {
		q += " LIMIT ? OFFSET ?"
		qArgs = append(qArgs, f.Limit, f.Start)
	}

	rows, err := r.db.QueryContext(ctx, q, qArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("auth_user list query: %v", err)
	}
	defer rows.Close()

	var users []*domain.AuthUser
	for rows.Next() {
		u, err := scanAuthUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (r *AuthUserRepository) Create(ctx context.Context, u *domain.AuthUser) (int, error) {
	q := `INSERT INTO auth_users (username, password_hash, description, enabled) VALUES (?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q, u.Username, u.PasswordHash, u.Description, boolToInt(u.Enabled))
	if err != nil {
		return 0, fmt.Errorf("auth_user create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *AuthUserRepository) Update(ctx context.Context, u *domain.AuthUser) error {
	q := `UPDATE auth_users SET username=?, password_hash=?, description=?, enabled=?, timestamp=CURRENT_TIMESTAMP
	      WHERE id_auth_users=?`
	_, err := r.db.ExecContext(ctx, q, u.Username, u.PasswordHash, u.Description, boolToInt(u.Enabled), u.ID)
	return err
}

func (r *AuthUserRepository) Delete(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM auth_users WHERE id_auth_users=?", id)
	return err
}

func scanAuthUser(s scanner) (*domain.AuthUser, error) {
	var u domain.AuthUser
	var enabled int
	err := s.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Description, &enabled, &u.Created, &u.Timestamp)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("auth user tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan auth_user: %v", err)
	}
	u.Enabled = enabled == 1
	return &u, nil
}

// ─── AuthGroupRepository ──────────────────────────────────────────────────────

type AuthGroupRepository struct{ db *sql.DB }

func NewAuthGroupRepository(db *sql.DB) *AuthGroupRepository {
	return &AuthGroupRepository{db: db}
}

func (r *AuthGroupRepository) FindByID(ctx context.Context, id int) (*domain.AuthGroup, error) {
	q := `SELECT id_auth_groups, group_name, description, enabled, created, timestamp
	      FROM auth_groups WHERE id_auth_groups=? LIMIT 1`
	g, err := scanAuthGroup(r.db.QueryRowContext(ctx, q, id))
	if err != nil {
		return nil, err
	}
	g.Members, err = r.ListMembers(ctx, g.ID)
	return g, err
}

func (r *AuthGroupRepository) FindByName(ctx context.Context, name string) (*domain.AuthGroup, error) {
	q := `SELECT id_auth_groups, group_name, description, enabled, created, timestamp
	      FROM auth_groups WHERE group_name=? LIMIT 1`
	return scanAuthGroup(r.db.QueryRowContext(ctx, q, name))
}

func (r *AuthGroupRepository) List(ctx context.Context, f domain.ListFilter) ([]*domain.AuthGroup, int, error) {
	base := `FROM auth_groups`
	var args []interface{}

	if f.Q != "" {
		like := "%" + f.Q + "%"
		base += ` WHERE (group_name LIKE ? OR description LIKE ?)`
		args = append(args, like, like)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("auth_group list count: %v", err)
	}

	q := `SELECT id_auth_groups, group_name, description, enabled, created, timestamp ` + base + ` ORDER BY group_name ASC`
	qArgs := append([]interface{}{}, args...)
	if f.Limit > 0 {
		q += " LIMIT ? OFFSET ?"
		qArgs = append(qArgs, f.Limit, f.Start)
	}

	rows, err := r.db.QueryContext(ctx, q, qArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("auth_group list query: %v", err)
	}
	defer rows.Close()

	var groups []*domain.AuthGroup
	for rows.Next() {
		g, err := scanAuthGroup(rows)
		if err != nil {
			return nil, 0, err
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	// Load member count per group (lightweight — hanya jumlah, bukan detail)
	for _, g := range groups {
		g.Members, _ = r.ListMembers(ctx, g.ID)
	}
	return groups, total, nil
}

// ListEnabled mengembalikan semua group yang enabled beserta members-nya.
// Digunakan oleh config generator — perlu password_hash member untuk generate userlist.
func (r *AuthGroupRepository) ListEnabled(ctx context.Context) ([]*domain.AuthGroup, error) {
	q := `SELECT id_auth_groups, group_name, description, enabled, created, timestamp
	      FROM auth_groups WHERE enabled=1 ORDER BY group_name ASC`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*domain.AuthGroup
	for rows.Next() {
		g, err := scanAuthGroup(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, g := range groups {
		g.Members, _ = r.ListMembers(ctx, g.ID)
	}
	return groups, nil
}

func (r *AuthGroupRepository) Create(ctx context.Context, g *domain.AuthGroup) (int, error) {
	q := `INSERT INTO auth_groups (group_name, description, enabled) VALUES (?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q, g.GroupName, g.Description, boolToInt(g.Enabled))
	if err != nil {
		return 0, fmt.Errorf("auth_group create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *AuthGroupRepository) Update(ctx context.Context, g *domain.AuthGroup) error {
	q := `UPDATE auth_groups SET group_name=?, description=?, enabled=?, timestamp=CURRENT_TIMESTAMP
	      WHERE id_auth_groups=?`
	_, err := r.db.ExecContext(ctx, q, g.GroupName, g.Description, boolToInt(g.Enabled), g.ID)
	return err
}

func (r *AuthGroupRepository) Delete(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM auth_groups WHERE id_auth_groups=?", id)
	return err
}

func (r *AuthGroupRepository) AddMember(ctx context.Context, groupID, userID int) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO auth_group_users (id_auth_groups, id_auth_users) VALUES (?, ?)`,
		groupID, userID)
	if err != nil {
		return fmt.Errorf("auth_group add member: %v", err)
	}
	return nil
}

func (r *AuthGroupRepository) RemoveMember(ctx context.Context, groupID, userID int) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM auth_group_users WHERE id_auth_groups=? AND id_auth_users=?`,
		groupID, userID)
	return err
}

func (r *AuthGroupRepository) ListMembers(ctx context.Context, groupID int) ([]*domain.AuthUser, error) {
	q := `SELECT u.id_auth_users, u.username, u.password_hash, u.description, u.enabled, u.created, u.timestamp
	      FROM auth_users u
	      INNER JOIN auth_group_users agu ON agu.id_auth_users = u.id_auth_users
	      WHERE agu.id_auth_groups=? ORDER BY u.username ASC`
	rows, err := r.db.QueryContext(ctx, q, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*domain.AuthUser
	for rows.Next() {
		u, err := scanAuthUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *AuthGroupRepository) IsMember(ctx context.Context, groupID, userID int) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM auth_group_users WHERE id_auth_groups=? AND id_auth_users=?`,
		groupID, userID).Scan(&count)
	return count > 0, err
}

func scanAuthGroup(s scanner) (*domain.AuthGroup, error) {
	var g domain.AuthGroup
	var enabled int
	err := s.Scan(&g.ID, &g.GroupName, &g.Description, &enabled, &g.Created, &g.Timestamp)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("auth group tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan auth_group: %v", err)
	}
	g.Enabled = enabled == 1
	return &g, nil
}

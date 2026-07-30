package sqlite

import (
	"context"
	"database/sql"
	"net"
	"time"

	"github.com/aefw/hapm/internal/domain"
)

type wafWhitelistRepo struct{ db *sql.DB }

func NewWAFWhitelistRepository(db *sql.DB) domain.WAFWhitelistRepository {
	return &wafWhitelistRepo{db: db}
}

const wafWhitelistType = "whitelist"

func (r *wafWhitelistRepo) List(ctx context.Context) ([]*domain.WAFWhitelist, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, ip_address, description, expires_at, created, timestamp
		 FROM waf_whitelist ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*domain.WAFWhitelist
	for rows.Next() {
		wl := &domain.WAFWhitelist{}
		if err := rows.Scan(&wl.ID, &wl.IPAddress, &wl.Description,
			&wl.ExpiresAt, &wl.Created, &wl.Timestamp); err != nil {
			return nil, err
		}
		list = append(list, wl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	bindings, err := loadDomainBindingsBatch(ctx, r.db, wafWhitelistType)
	if err != nil {
		return nil, err
	}
	for _, wl := range list {
		wl.DomainIDs = ensureIntSlice(bindings[wl.ID])
	}
	return list, nil
}

func (r *wafWhitelistRepo) FindByID(ctx context.Context, id int) (*domain.WAFWhitelist, error) {
	wl := &domain.WAFWhitelist{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, ip_address, description, expires_at, created, timestamp
		 FROM waf_whitelist WHERE id = ?`, id).
		Scan(&wl.ID, &wl.IPAddress, &wl.Description, &wl.ExpiresAt, &wl.Created, &wl.Timestamp)
	if err != nil {
		return nil, err
	}
	ids, err := loadDomainBindings(ctx, r.db, wafWhitelistType, wl.ID)
	if err != nil {
		return nil, err
	}
	wl.DomainIDs = ensureIntSlice(ids)
	return wl, nil
}

func (r *wafWhitelistRepo) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	now := time.Now()
	rows, err := r.db.QueryContext(ctx, `SELECT ip_address, expires_at FROM waf_whitelist`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false, nil
	}

	for rows.Next() {
		var entry string
		var expiresAt *time.Time
		if err := rows.Scan(&entry, &expiresAt); err != nil {
			continue
		}
		if expiresAt != nil && now.After(*expiresAt) {
			continue // entri sudah kadaluarsa
		}
		if matchIPOrCIDR(clientIP, entry) {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (r *wafWhitelistRepo) Create(ctx context.Context, wl *domain.WAFWhitelist) error {
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO waf_whitelist (ip_address, description, expires_at) VALUES (?, ?, ?)`,
		wl.IPAddress, wl.Description, wl.ExpiresAt)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	wl.ID = int(id)
	return saveDomainBindings(ctx, r.db, wafWhitelistType, wl.ID, wl.DomainIDs)
}

func (r *wafWhitelistRepo) Delete(ctx context.Context, id int) error {
	if err := deleteDomainBindings(ctx, r.db, wafWhitelistType, id); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM waf_whitelist WHERE id = ?`, id)
	return err
}

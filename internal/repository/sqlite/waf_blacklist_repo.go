package sqlite

import (
	"context"
	"database/sql"
	"net"

	"github.com/aefw/hapm/internal/domain"
)

type wafBlacklistRepo struct{ db *sql.DB }

func NewWAFBlacklistRepository(db *sql.DB) domain.WAFBlacklistRepository {
	return &wafBlacklistRepo{db: db}
}

const wafBlacklistType = "blacklist"

func (r *wafBlacklistRepo) List(ctx context.Context) ([]*domain.WAFBlacklist, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, ip_address, reason, expires_at, created, timestamp
		 FROM waf_blacklist ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*domain.WAFBlacklist
	for rows.Next() {
		bl := &domain.WAFBlacklist{}
		if err := rows.Scan(&bl.ID, &bl.IPAddress, &bl.Reason, &bl.ExpiresAt,
			&bl.Created, &bl.Timestamp); err != nil {
			return nil, err
		}
		list = append(list, bl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	bindings, err := loadDomainBindingsBatch(ctx, r.db, wafBlacklistType)
	if err != nil {
		return nil, err
	}
	for _, bl := range list {
		bl.DomainIDs = ensureIntSlice(bindings[bl.ID])
	}
	return list, nil
}

func (r *wafBlacklistRepo) FindByID(ctx context.Context, id int) (*domain.WAFBlacklist, error) {
	bl := &domain.WAFBlacklist{}
	err := r.db.QueryRowContext(ctx,
		`SELECT id, ip_address, reason, expires_at, created, timestamp
		 FROM waf_blacklist WHERE id = ?`, id).
		Scan(&bl.ID, &bl.IPAddress, &bl.Reason, &bl.ExpiresAt, &bl.Created, &bl.Timestamp)
	if err != nil {
		return nil, err
	}
	ids, err := loadDomainBindings(ctx, r.db, wafBlacklistType, bl.ID)
	if err != nil {
		return nil, err
	}
	bl.DomainIDs = ensureIntSlice(ids)
	return bl, nil
}

// IsBlacklisted cek apakah IP cocok dengan salah satu entri blacklist (termasuk CIDR).
// Entri yang sudah expired diabaikan.
func (r *wafBlacklistRepo) IsBlacklisted(ctx context.Context, ip string) (bool, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT ip_address FROM waf_blacklist
		 WHERE (expires_at IS NULL OR expires_at > datetime('now'))`)
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
		if err := rows.Scan(&entry); err != nil {
			continue
		}
		if matchIPOrCIDR(clientIP, entry) {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (r *wafBlacklistRepo) Create(ctx context.Context, bl *domain.WAFBlacklist) error {
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO waf_blacklist (ip_address, reason, expires_at) VALUES (?, ?, ?)`,
		bl.IPAddress, bl.Reason, bl.ExpiresAt)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	bl.ID = int(id)
	return saveDomainBindings(ctx, r.db, wafBlacklistType, bl.ID, bl.DomainIDs)
}

func (r *wafBlacklistRepo) Delete(ctx context.Context, id int) error {
	if err := deleteDomainBindings(ctx, r.db, wafBlacklistType, id); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM waf_blacklist WHERE id = ?`, id)
	return err
}

func (r *wafBlacklistRepo) CleanExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM waf_blacklist WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')`)
	return err
}

// matchIPOrCIDR cocokkan IP dengan entri blacklist (bisa IP tunggal atau CIDR)
func matchIPOrCIDR(clientIP net.IP, entry string) bool {
	if _, ipNet, err := net.ParseCIDR(entry); err == nil {
		return ipNet.Contains(clientIP)
	}
	if entryIP := net.ParseIP(entry); entryIP != nil {
		return clientIP.Equal(entryIP)
	}
	return false
}

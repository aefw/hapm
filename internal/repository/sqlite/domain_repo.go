package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
)

// DomainRepository adalah implementasi SQLite untuk domain.DomainRepository
type DomainRepository struct{ db *sql.DB }

func NewDomainRepository(db *sql.DB) *DomainRepository {
	return &DomainRepository{db: db}
}

const domainSelectCols = `
	SELECT d.id_domains, d.domain_name, d.id_backend_pools, d.ssl_mode,
	       d.cert_uuid, d.http_redirect, d.enabled, d.description, d.created, d.timestamp,
	       bp.id_backend_pools, bp.name, bp.description, bp.algorithm,
	       bp.timeout_connect, bp.timeout_server, bp.health_check,
	       bp.health_check_type, bp.health_check_config, bp.created, bp.timestamp,
	       ag.id_auth_groups, ag.group_name, ag.description, ag.enabled
	FROM domains d
	LEFT JOIN backend_pools bp ON bp.id_backend_pools = d.id_backend_pools
	LEFT JOIN auth_groups ag   ON ag.id_auth_groups   = d.id_auth_groups`

func (r *DomainRepository) FindByID(ctx context.Context, id int) (*domain.DomainEntry, error) {
	return scanDomain(r.db.QueryRowContext(ctx, domainSelectCols+` WHERE d.id_domains=? LIMIT 1`, id))
}

func (r *DomainRepository) FindByDomainName(ctx context.Context, name string) (*domain.DomainEntry, error) {
	return scanDomain(r.db.QueryRowContext(ctx, domainSelectCols+` WHERE d.domain_name=? LIMIT 1`, name))
}

func (r *DomainRepository) List(ctx context.Context, f domain.ListFilter) ([]*domain.DomainEntry, int, error) {
	where := ""
	var args []interface{}

	if f.Q != "" {
		like := "%" + f.Q + "%"
		where = ` WHERE (d.domain_name LIKE ? OR d.description LIKE ?)`
		args = append(args, like, like)
	}
	if f.AuthGroupID != nil {
		if where == "" {
			where = ` WHERE d.id_auth_groups = ?`
		} else {
			where += ` AND d.id_auth_groups = ?`
		}
		args = append(args, *f.AuthGroupID)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM domains d"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := domainSelectCols + where + ` ORDER BY d.domain_name ASC`
	qArgs := append([]interface{}{}, args...)
	if f.Limit > 0 {
		q += " LIMIT ? OFFSET ?"
		qArgs = append(qArgs, f.Limit, f.Start)
	}

	items, err := r.queryDomains(ctx, q, qArgs...)
	return items, total, err
}

func (r *DomainRepository) ListEnabled(ctx context.Context) ([]*domain.DomainEntry, error) {
	return r.queryDomains(ctx, domainSelectCols+` WHERE d.enabled=1 ORDER BY d.domain_name ASC`)
}

func (r *DomainRepository) Create(ctx context.Context, d *domain.DomainEntry) (int, error) {
	q := `INSERT INTO domains (domain_name, id_backend_pools, ssl_mode, cert_uuid,
	             id_auth_groups, http_redirect, enabled, description)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q,
		d.DomainName, d.BackendPoolID, string(d.SSLMode), d.CertUUID,
		d.AuthGroupID, boolToInt(d.HTTPRedirect), boolToInt(d.Enabled), d.Description)
	if err != nil {
		return 0, fmt.Errorf("domain create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *DomainRepository) Update(ctx context.Context, d *domain.DomainEntry) error {
	q := `UPDATE domains SET domain_name=?, id_backend_pools=?, ssl_mode=?, cert_uuid=?,
	             id_auth_groups=?, http_redirect=?, enabled=?, description=?, timestamp=CURRENT_TIMESTAMP
	      WHERE id_domains=?`
	_, err := r.db.ExecContext(ctx, q,
		d.DomainName, d.BackendPoolID, string(d.SSLMode), d.CertUUID,
		d.AuthGroupID, boolToInt(d.HTTPRedirect), boolToInt(d.Enabled), d.Description, d.ID)
	return err
}

func (r *DomainRepository) Delete(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM domains WHERE id_domains=?", id)
	return err
}

func (r *DomainRepository) queryDomains(ctx context.Context, q string, args ...interface{}) ([]*domain.DomainEntry, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var domains []*domain.DomainEntry
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		domains = append(domains, d)
	}
	return domains, rows.Err()
}

func scanDomain(s scanner) (*domain.DomainEntry, error) {
	var d domain.DomainEntry
	var certUUID sql.NullString
	var desc sql.NullString
	var httpRedirect, enabled int

	// JOIN backend_pools
	var bpID sql.NullInt64
	var bpName, bpDesc, bpAlgo sql.NullString
	var bpTimeoutConnect, bpTimeoutServer, bpHealthCheck sql.NullInt64
	var bpHCType, bpHCConfig sql.NullString
	var bpCreated, bpTimestamp sql.NullTime

	// JOIN auth_groups
	var agID sql.NullInt64
	var agName, agDesc sql.NullString
	var agEnabled sql.NullInt64

	err := s.Scan(
		&d.ID, &d.DomainName, &d.BackendPoolID, &d.SSLMode,
		&certUUID, &httpRedirect, &enabled, &desc, &d.Created, &d.Timestamp,
		&bpID, &bpName, &bpDesc, &bpAlgo,
		&bpTimeoutConnect, &bpTimeoutServer, &bpHealthCheck,
		&bpHCType, &bpHCConfig, &bpCreated, &bpTimestamp,
		&agID, &agName, &agDesc, &agEnabled,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("domain tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan domain: %v", err)
	}

	if certUUID.Valid && certUUID.String != "" {
		d.CertUUID = &certUUID.String
	}
	d.HTTPRedirect = httpRedirect == 1
	d.Enabled = enabled == 1
	d.Description = desc.String

	if bpID.Valid {
		hcConf := unmarshalHealthCheck(bpHCType.String, bpHCConfig.String)
		d.BackendPool = &domain.BackendPool{
			ID:              int(bpID.Int64),
			Name:            bpName.String,
			Description:     bpDesc.String,
			Algorithm:       domain.Algorithm(bpAlgo.String),
			TimeoutConnect:  int(bpTimeoutConnect.Int64),
			TimeoutServer:   int(bpTimeoutServer.Int64),
			HealthCheck:     hcConf.IsEnabled(),
			HealthCheckConf: hcConf,
			Created:         bpCreated.Time,
			Timestamp:       bpTimestamp.Time,
		}
	}

	if agID.Valid {
		id := int(agID.Int64)
		d.AuthGroupID = &id
		d.AuthGroup = &domain.AuthGroup{
			ID:          id,
			GroupName:   agName.String,
			Description: agDesc.String,
			Enabled:     agEnabled.Int64 == 1,
		}
	}

	return &d, nil
}

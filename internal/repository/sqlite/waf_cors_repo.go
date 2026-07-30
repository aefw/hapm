package sqlite

import (
	"context"
	"database/sql"

	"github.com/aefw/hapm/internal/domain"
)

const wafCORSType = "cors"

type wafCORSRepo struct{ db *sql.DB }

func NewWAFCORSRepository(db *sql.DB) domain.WAFCORSRepository {
	return &wafCORSRepo{db: db}
}

func (r *wafCORSRepo) List(ctx context.Context) ([]*domain.WAFCORSRule, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, path_pattern, allowed_origins, allowed_methods, allowed_headers,
		        expose_headers, allow_credentials, max_age_seconds, enabled, priority,
		        created, timestamp
		 FROM waf_cors_rules ORDER BY priority DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := r.scanRows(rows)
	if err != nil {
		return nil, err
	}
	bindings, err := loadDomainBindingsBatch(ctx, r.db, wafCORSType)
	if err != nil {
		return nil, err
	}
	for _, rule := range list {
		rule.DomainIDs = ensureIntSlice(bindings[rule.ID])
	}
	return list, nil
}

func (r *wafCORSRepo) ListEnabled(ctx context.Context) ([]*domain.WAFCORSRule, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, path_pattern, allowed_origins, allowed_methods, allowed_headers,
		        expose_headers, allow_credentials, max_age_seconds, enabled, priority,
		        created, timestamp
		 FROM waf_cors_rules WHERE enabled = 1 ORDER BY priority DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := r.scanRows(rows)
	if err != nil {
		return nil, err
	}
	bindings, err := loadDomainBindingsBatch(ctx, r.db, wafCORSType)
	if err != nil {
		return nil, err
	}
	for _, rule := range list {
		rule.DomainIDs = ensureIntSlice(bindings[rule.ID])
	}
	return list, nil
}

func (r *wafCORSRepo) FindByID(ctx context.Context, id int) (*domain.WAFCORSRule, error) {
	rule := &domain.WAFCORSRule{}
	var creds, enabled int
	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, path_pattern, allowed_origins, allowed_methods, allowed_headers,
		        expose_headers, allow_credentials, max_age_seconds, enabled, priority,
		        created, timestamp
		 FROM waf_cors_rules WHERE id = ?`, id).
		Scan(&rule.ID, &rule.Name, &rule.PathPattern, &rule.AllowedOrigins,
			&rule.AllowedMethods, &rule.AllowedHeaders, &rule.ExposeHeaders,
			&creds, &rule.MaxAgeSeconds, &enabled, &rule.Priority,
			&rule.Created, &rule.Timestamp)
	if err != nil {
		return nil, err
	}
	rule.AllowCredentials = creds == 1
	rule.Enabled = enabled == 1
	ids, err := loadDomainBindings(ctx, r.db, wafCORSType, rule.ID)
	if err != nil {
		return nil, err
	}
	rule.DomainIDs = ensureIntSlice(ids)
	return rule, nil
}

func (r *wafCORSRepo) Create(ctx context.Context, rule *domain.WAFCORSRule) error {
	creds, enabled := 0, 0
	if rule.AllowCredentials {
		creds = 1
	}
	if rule.Enabled {
		enabled = 1
	}
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO waf_cors_rules
		 (name, path_pattern, allowed_origins, allowed_methods, allowed_headers,
		  expose_headers, allow_credentials, max_age_seconds, enabled, priority)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.Name, rule.PathPattern, rule.AllowedOrigins, rule.AllowedMethods,
		rule.AllowedHeaders, rule.ExposeHeaders, creds, rule.MaxAgeSeconds,
		enabled, rule.Priority)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	rule.ID = int(id)
	return saveDomainBindings(ctx, r.db, wafCORSType, rule.ID, rule.DomainIDs)
}

func (r *wafCORSRepo) Update(ctx context.Context, rule *domain.WAFCORSRule) error {
	creds, enabled := 0, 0
	if rule.AllowCredentials {
		creds = 1
	}
	if rule.Enabled {
		enabled = 1
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE waf_cors_rules SET name=?, path_pattern=?, allowed_origins=?,
		 allowed_methods=?, allowed_headers=?, expose_headers=?,
		 allow_credentials=?, max_age_seconds=?, enabled=?, priority=?,
		 timestamp=CURRENT_TIMESTAMP WHERE id=?`,
		rule.Name, rule.PathPattern, rule.AllowedOrigins, rule.AllowedMethods,
		rule.AllowedHeaders, rule.ExposeHeaders, creds, rule.MaxAgeSeconds,
		enabled, rule.Priority, rule.ID)
	if err != nil {
		return err
	}
	return saveDomainBindings(ctx, r.db, wafCORSType, rule.ID, rule.DomainIDs)
}

func (r *wafCORSRepo) Delete(ctx context.Context, id int) error {
	if err := deleteDomainBindings(ctx, r.db, wafCORSType, id); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM waf_cors_rules WHERE id = ?`, id)
	return err
}

func (r *wafCORSRepo) scanRows(rows *sql.Rows) ([]*domain.WAFCORSRule, error) {
	var list []*domain.WAFCORSRule
	for rows.Next() {
		rule := &domain.WAFCORSRule{}
		var creds, enabled int
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.PathPattern, &rule.AllowedOrigins,
			&rule.AllowedMethods, &rule.AllowedHeaders, &rule.ExposeHeaders,
			&creds, &rule.MaxAgeSeconds, &enabled, &rule.Priority,
			&rule.Created, &rule.Timestamp); err != nil {
			return nil, err
		}
		rule.AllowCredentials = creds == 1
		rule.Enabled = enabled == 1
		list = append(list, rule)
	}
	return list, rows.Err()
}

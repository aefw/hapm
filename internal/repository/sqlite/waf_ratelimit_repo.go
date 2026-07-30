package sqlite

import (
	"context"
	"database/sql"

	"github.com/aefw/hapm/internal/domain"
)

const wafRateLimitType = "rate_limit"

type wafRateLimitRepo struct{ db *sql.DB }

func NewWAFRateLimitRepository(db *sql.DB) domain.WAFRateLimitRepository {
	return &wafRateLimitRepo{db: db}
}

func (r *wafRateLimitRepo) List(ctx context.Context) ([]*domain.WAFRateLimit, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, path_pattern, max_requests, window_seconds,
		        block_duration_seconds, auto_blacklist_threshold, enabled, created, timestamp
		 FROM waf_rate_limits ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := r.scanRows(rows)
	if err != nil {
		return nil, err
	}
	bindings, err := loadDomainBindingsBatch(ctx, r.db, wafRateLimitType)
	if err != nil {
		return nil, err
	}
	for _, rl := range list {
		rl.DomainIDs = ensureIntSlice(bindings[rl.ID])
	}
	return list, nil
}

func (r *wafRateLimitRepo) ListEnabled(ctx context.Context) ([]*domain.WAFRateLimit, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, path_pattern, max_requests, window_seconds,
		        block_duration_seconds, auto_blacklist_threshold, enabled, created, timestamp
		 FROM waf_rate_limits WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := r.scanRows(rows)
	if err != nil {
		return nil, err
	}
	bindings, err := loadDomainBindingsBatch(ctx, r.db, wafRateLimitType)
	if err != nil {
		return nil, err
	}
	for _, rl := range list {
		rl.DomainIDs = ensureIntSlice(bindings[rl.ID])
	}
	return list, nil
}

func (r *wafRateLimitRepo) FindByID(ctx context.Context, id int) (*domain.WAFRateLimit, error) {
	rl := &domain.WAFRateLimit{}
	var enabled int
	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, path_pattern, max_requests, window_seconds,
		        block_duration_seconds, auto_blacklist_threshold, enabled, created, timestamp
		 FROM waf_rate_limits WHERE id = ?`, id).
		Scan(&rl.ID, &rl.Name, &rl.PathPattern, &rl.MaxRequests, &rl.WindowSeconds,
			&rl.BlockDurationSeconds, &rl.AutoBlacklistThreshold, &enabled,
			&rl.Created, &rl.Timestamp)
	if err != nil {
		return nil, err
	}
	rl.Enabled = enabled == 1
	ids, err := loadDomainBindings(ctx, r.db, wafRateLimitType, rl.ID)
	if err != nil {
		return nil, err
	}
	rl.DomainIDs = ensureIntSlice(ids)
	return rl, nil
}

func (r *wafRateLimitRepo) Create(ctx context.Context, rl *domain.WAFRateLimit) error {
	enabled := 0
	if rl.Enabled {
		enabled = 1
	}
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO waf_rate_limits
		 (name, path_pattern, max_requests, window_seconds, block_duration_seconds,
		  auto_blacklist_threshold, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rl.Name, rl.PathPattern, rl.MaxRequests, rl.WindowSeconds,
		rl.BlockDurationSeconds, rl.AutoBlacklistThreshold, enabled)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	rl.ID = int(id)
	return saveDomainBindings(ctx, r.db, wafRateLimitType, rl.ID, rl.DomainIDs)
}

func (r *wafRateLimitRepo) Update(ctx context.Context, rl *domain.WAFRateLimit) error {
	enabled := 0
	if rl.Enabled {
		enabled = 1
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE waf_rate_limits SET name=?, path_pattern=?, max_requests=?,
		 window_seconds=?, block_duration_seconds=?, auto_blacklist_threshold=?,
		 enabled=?, timestamp=CURRENT_TIMESTAMP WHERE id=?`,
		rl.Name, rl.PathPattern, rl.MaxRequests, rl.WindowSeconds,
		rl.BlockDurationSeconds, rl.AutoBlacklistThreshold, enabled, rl.ID)
	if err != nil {
		return err
	}
	return saveDomainBindings(ctx, r.db, wafRateLimitType, rl.ID, rl.DomainIDs)
}

func (r *wafRateLimitRepo) Delete(ctx context.Context, id int) error {
	if err := deleteDomainBindings(ctx, r.db, wafRateLimitType, id); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM waf_rate_limits WHERE id = ?`, id)
	return err
}

func (r *wafRateLimitRepo) scanRows(rows *sql.Rows) ([]*domain.WAFRateLimit, error) {
	var list []*domain.WAFRateLimit
	for rows.Next() {
		rl := &domain.WAFRateLimit{}
		var enabled int
		if err := rows.Scan(&rl.ID, &rl.Name, &rl.PathPattern, &rl.MaxRequests,
			&rl.WindowSeconds, &rl.BlockDurationSeconds, &rl.AutoBlacklistThreshold,
			&enabled, &rl.Created, &rl.Timestamp); err != nil {
			return nil, err
		}
		rl.Enabled = enabled == 1
		list = append(list, rl)
	}
	return list, rows.Err()
}

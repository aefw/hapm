package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/aefw/hapm/internal/domain"
)

type wafGenerationRepo struct{ db *sql.DB }

func NewWAFGenerationRepository(db *sql.DB) domain.WAFGenerationRepository {
	return &wafGenerationRepo{db: db}
}

// LoadForGeneration mengambil semua WAF data yang diperlukan untuk config generation.
// Blacklist dan Whitelist difilter dari entri yang sudah expired.
// Domain names di-load untuk keperluan generate ACL domain-scoped.
func (r *wafGenerationRepo) LoadForGeneration(ctx context.Context) (*domain.WAFConfig, error) {
	now := time.Now()

	// Domain names: id → name
	domainNames, err := r.loadDomainNames(ctx)
	if err != nil {
		return nil, err
	}

	// WAF Rules (enabled only)
	rules, err := r.loadRules(ctx)
	if err != nil {
		return nil, err
	}

	// Blacklist (non-expired)
	blacklist, err := r.loadBlacklist(ctx, now)
	if err != nil {
		return nil, err
	}

	// Whitelist (non-expired)
	whitelist, err := r.loadWhitelist(ctx, now)
	if err != nil {
		return nil, err
	}

	// Rate Limits (enabled only)
	rateLimits, err := r.loadRateLimits(ctx)
	if err != nil {
		return nil, err
	}

	// CORS Rules (enabled only)
	corsRules, err := r.loadCORSRules(ctx)
	if err != nil {
		return nil, err
	}

	// Domain bindings untuk setiap rule type
	ruleBindings, err := loadDomainBindingsBatch(ctx, r.db, wafRuleType)
	if err != nil {
		return nil, err
	}
	blBindings, err := loadDomainBindingsBatch(ctx, r.db, wafBlacklistType)
	if err != nil {
		return nil, err
	}
	wlBindings, err := loadDomainBindingsBatch(ctx, r.db, wafWhitelistType)
	if err != nil {
		return nil, err
	}
	rlBindings, err := loadDomainBindingsBatch(ctx, r.db, wafRateLimitType)
	if err != nil {
		return nil, err
	}
	corsBindings, err := loadDomainBindingsBatch(ctx, r.db, wafCORSType)
	if err != nil {
		return nil, err
	}

	for _, r := range rules {
		r.DomainIDs = ensureIntSlice(ruleBindings[r.ID])
	}
	for _, bl := range blacklist {
		bl.DomainIDs = ensureIntSlice(blBindings[bl.ID])
	}
	for _, wl := range whitelist {
		wl.DomainIDs = ensureIntSlice(wlBindings[wl.ID])
	}
	for _, rl := range rateLimits {
		rl.DomainIDs = ensureIntSlice(rlBindings[rl.ID])
	}
	for _, cr := range corsRules {
		cr.DomainIDs = ensureIntSlice(corsBindings[cr.ID])
	}

	return &domain.WAFConfig{
		Rules:       rules,
		Blacklist:   blacklist,
		Whitelist:   whitelist,
		RateLimits:  rateLimits,
		CORSRules:   corsRules,
		DomainNames: domainNames,
	}, nil
}

func (r *wafGenerationRepo) loadDomainNames(ctx context.Context) (map[int]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id_domains, domain_name FROM domains WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := make(map[int]string)
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		names[id] = name
	}
	return names, rows.Err()
}

func (r *wafGenerationRepo) loadRules(ctx context.Context) ([]*domain.WAFRule, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id_waf_rules, name, rule_type, value, action, enabled, created, timestamp
		 FROM waf_rules WHERE enabled = 1 AND action = 'deny' ORDER BY id_waf_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*domain.WAFRule
	for rows.Next() {
		rule := &domain.WAFRule{}
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.RuleType, &rule.Value,
			&rule.Action, &enabled, &rule.Created, &rule.Timestamp); err != nil {
			return nil, err
		}
		rule.Enabled = enabled == 1
		list = append(list, rule)
	}
	return list, rows.Err()
}

func (r *wafGenerationRepo) loadBlacklist(ctx context.Context, now time.Time) ([]*domain.WAFBlacklist, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, ip_address, reason, expires_at, created, timestamp
		 FROM waf_blacklist
		 WHERE expires_at IS NULL OR expires_at > ?
		 ORDER BY id`, now)
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
	return list, rows.Err()
}

func (r *wafGenerationRepo) loadWhitelist(ctx context.Context, now time.Time) ([]*domain.WAFWhitelist, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, ip_address, description, expires_at, created, timestamp
		 FROM waf_whitelist
		 WHERE expires_at IS NULL OR expires_at > ?
		 ORDER BY id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*domain.WAFWhitelist
	for rows.Next() {
		wl := &domain.WAFWhitelist{}
		if err := rows.Scan(&wl.ID, &wl.IPAddress, &wl.Description, &wl.ExpiresAt,
			&wl.Created, &wl.Timestamp); err != nil {
			return nil, err
		}
		list = append(list, wl)
	}
	return list, rows.Err()
}

func (r *wafGenerationRepo) loadRateLimits(ctx context.Context) ([]*domain.WAFRateLimit, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, path_pattern, max_requests, window_seconds,
		        block_duration_seconds, auto_blacklist_threshold, enabled, created, timestamp
		 FROM waf_rate_limits WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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

func (r *wafGenerationRepo) loadCORSRules(ctx context.Context) ([]*domain.WAFCORSRule, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, path_pattern, allowed_origins, allowed_methods, allowed_headers,
		        expose_headers, allow_credentials, max_age_seconds, enabled, priority,
		        created, timestamp
		 FROM waf_cors_rules WHERE enabled = 1 ORDER BY priority DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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

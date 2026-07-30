package sqlite

import (
	"context"
	"database/sql"

	"github.com/aefw/hapm/internal/domain"
)

type wafRuleRepo struct{ db *sql.DB }

func NewWAFRuleRepository(db *sql.DB) domain.WAFRuleRepository {
	return &wafRuleRepo{db: db}
}

const wafRuleType = "rule"

func (r *wafRuleRepo) List(ctx context.Context) ([]*domain.WAFRule, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id_waf_rules, name, rule_type, value, action, enabled, created, timestamp
		 FROM waf_rules ORDER BY id_waf_rules`)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	bindings, err := loadDomainBindingsBatch(ctx, r.db, wafRuleType)
	if err != nil {
		return nil, err
	}
	for _, rule := range list {
		rule.DomainIDs = ensureIntSlice(bindings[rule.ID])
	}
	return list, nil
}

func (r *wafRuleRepo) FindByID(ctx context.Context, id int) (*domain.WAFRule, error) {
	rule := &domain.WAFRule{}
	var enabled int
	err := r.db.QueryRowContext(ctx,
		`SELECT id_waf_rules, name, rule_type, value, action, enabled, created, timestamp
		 FROM waf_rules WHERE id_waf_rules = ?`, id).
		Scan(&rule.ID, &rule.Name, &rule.RuleType, &rule.Value,
			&rule.Action, &enabled, &rule.Created, &rule.Timestamp)
	if err != nil {
		return nil, err
	}
	rule.Enabled = enabled == 1
	ids, err := loadDomainBindings(ctx, r.db, wafRuleType, rule.ID)
	if err != nil {
		return nil, err
	}
	rule.DomainIDs = ensureIntSlice(ids)
	return rule, nil
}

func (r *wafRuleRepo) Create(ctx context.Context, rule *domain.WAFRule) error {
	enabled := 0
	if rule.Enabled {
		enabled = 1
	}
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO waf_rules (name, rule_type, value, action, enabled) VALUES (?, ?, ?, ?, ?)`,
		rule.Name, rule.RuleType, rule.Value, rule.Action, enabled)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	rule.ID = int(id)
	return saveDomainBindings(ctx, r.db, wafRuleType, rule.ID, rule.DomainIDs)
}

func (r *wafRuleRepo) Update(ctx context.Context, rule *domain.WAFRule) error {
	enabled := 0
	if rule.Enabled {
		enabled = 1
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE waf_rules SET name = ?, rule_type = ?, value = ?, action = ?, enabled = ?,
		 timestamp = CURRENT_TIMESTAMP WHERE id_waf_rules = ?`,
		rule.Name, rule.RuleType, rule.Value, rule.Action, enabled, rule.ID)
	if err != nil {
		return err
	}
	return saveDomainBindings(ctx, r.db, wafRuleType, rule.ID, rule.DomainIDs)
}

func (r *wafRuleRepo) Delete(ctx context.Context, id int) error {
	if err := deleteDomainBindings(ctx, r.db, wafRuleType, id); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM waf_rules WHERE id_waf_rules = ?`, id)
	return err
}

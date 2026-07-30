package sqlite

import (
	"context"
	"database/sql"
)

// saveDomainBindings menghapus binding lama dan menyimpan yang baru.
// domainIDs kosong = hapus semua binding (rule berlaku global).
func saveDomainBindings(ctx context.Context, db *sql.DB, ruleType string, ruleID int, domainIDs []int) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM waf_domain_bindings WHERE rule_type = ? AND rule_id = ?`,
		ruleType, ruleID)
	if err != nil {
		return err
	}
	for _, did := range domainIDs {
		_, err := db.ExecContext(ctx,
			`INSERT OR IGNORE INTO waf_domain_bindings (rule_type, rule_id, domain_id) VALUES (?, ?, ?)`,
			ruleType, ruleID, did)
		if err != nil {
			return err
		}
	}
	return nil
}

// loadDomainBindings mengambil domain_id yang terikat ke rule tertentu.
func loadDomainBindings(ctx context.Context, db *sql.DB, ruleType string, ruleID int) ([]int, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT domain_id FROM waf_domain_bindings WHERE rule_type = ? AND rule_id = ? ORDER BY domain_id`,
		ruleType, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// deleteDomainBindings menghapus semua binding untuk rule yang dihapus.
func deleteDomainBindings(ctx context.Context, db *sql.DB, ruleType string, ruleID int) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM waf_domain_bindings WHERE rule_type = ? AND rule_id = ?`,
		ruleType, ruleID)
	return err
}

// loadDomainBindingsBatch mengambil domain_id untuk banyak rule sekaligus.
// Mengembalikan map[ruleID][]domainID.
func loadDomainBindingsBatch(ctx context.Context, db *sql.DB, ruleType string) (map[int][]int, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT rule_id, domain_id FROM waf_domain_bindings WHERE rule_type = ? ORDER BY rule_id, domain_id`,
		ruleType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int][]int)
	for rows.Next() {
		var ruleID, domainID int
		if err := rows.Scan(&ruleID, &domainID); err != nil {
			return nil, err
		}
		result[ruleID] = append(result[ruleID], domainID)
	}
	return result, rows.Err()
}

// loadFromTx adalah variasi loadDomainBindingsBatch yang menerima *sql.Tx.
func loadBindingsBatchTx(ctx context.Context, tx *sql.Tx, ruleType string) (map[int][]int, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT rule_id, domain_id FROM waf_domain_bindings WHERE rule_type = ? ORDER BY rule_id, domain_id`,
		ruleType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int][]int)
	for rows.Next() {
		var ruleID, domainID int
		if err := rows.Scan(&ruleID, &domainID); err != nil {
			return nil, err
		}
		result[ruleID] = append(result[ruleID], domainID)
	}
	return result, rows.Err()
}

// ensureIntSlice mengembalikan []int yang tidak pernah nil.
func ensureIntSlice(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

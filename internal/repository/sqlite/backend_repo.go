package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
)

// BackendRepository adalah implementasi SQLite untuk domain.BackendRepository
type BackendRepository struct{ db *sql.DB }

func NewBackendRepository(db *sql.DB) *BackendRepository {
	return &BackendRepository{db: db}
}

// ─── Pool ─────────────────────────────────────────────────────────────────────

// poolSelectCols adalah kolom SELECT untuk backend_pools
const poolSelectCols = `SELECT id_backend_pools, name, description, algorithm,
    timeout_connect, timeout_server, health_check,
    health_check_type, health_check_config, protocol, ssl_mode, forward_headers,
    created, timestamp
    FROM backend_pools`

func (r *BackendRepository) FindPoolByID(ctx context.Context, id int) (*domain.BackendPool, error) {
	q := poolSelectCols + ` WHERE id_backend_pools=? LIMIT 1`
	pool, err := scanPool(r.db.QueryRowContext(ctx, q, id))
	if err != nil || pool == nil {
		return pool, err
	}
	// Load servers
	pool.Servers, err = r.listServers(ctx, pool.ID)
	return pool, err
}

func (r *BackendRepository) FindPoolByName(ctx context.Context, name string) (*domain.BackendPool, error) {
	q := poolSelectCols + ` WHERE name=? LIMIT 1`
	return scanPool(r.db.QueryRowContext(ctx, q, name))
}

func (r *BackendRepository) ListPools(ctx context.Context, f domain.ListFilter) ([]*domain.BackendPool, int, error) {
	base := `FROM backend_pools`
	var args []interface{}

	if f.Q != "" {
		like := "%" + f.Q + "%"
		base += ` WHERE (name LIKE ? OR description LIKE ?)`
		args = append(args, like, like)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	selectBase := `SELECT id_backend_pools, name, description, algorithm,
	    timeout_connect, timeout_server, health_check,
	    health_check_type, health_check_config, protocol, ssl_mode, forward_headers,
	    created, timestamp ` + base + ` ORDER BY name ASC`
	qArgs := append([]interface{}{}, args...)
	if f.Limit > 0 {
		selectBase += " LIMIT ? OFFSET ?"
		qArgs = append(qArgs, f.Limit, f.Start)
	}

	rows, err := r.db.QueryContext(ctx, selectBase, qArgs...)
	if err != nil {
		return nil, 0, err
	}
	// Kumpulkan semua pool terlebih dahulu sebelum menutup cursor,
	// baru load servers setelah rows.Close() agar tidak terjadi nested query deadlock.
	var pools []*domain.BackendPool
	for rows.Next() {
		p, err := scanPool(rows)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		pools = append(pools, p)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	// Load servers setelah cursor ditutup
	for _, p := range pools {
		p.Servers, _ = r.listServers(ctx, p.ID)
	}
	return pools, total, nil
}

func (r *BackendRepository) CreatePool(ctx context.Context, p *domain.BackendPool) (int, error) {
	hcType, hcConfig := marshalHealthCheck(p.HealthCheckConf)
	q := `INSERT INTO backend_pools (name, description, algorithm, timeout_connect, timeout_server,
	             health_check, health_check_type, health_check_config,
	             protocol, ssl_mode, forward_headers)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q,
		p.Name, p.Description, string(p.Algorithm),
		p.TimeoutConnect, p.TimeoutServer,
		boolToInt(p.HealthCheckConf.IsEnabled()), hcType, hcConfig,
		string(p.Protocol), string(p.SSLMode), boolToInt(p.ForwardHeaders))
	if err != nil {
		return 0, fmt.Errorf("pool create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

// CreatePoolWithServers membuat pool dan server-servernya secara atomik dalam satu transaksi.
// Jika ada server yang gagal disimpan, seluruh operasi di-rollback (pool pun tidak tersimpan).
func (r *BackendRepository) CreatePoolWithServers(ctx context.Context, p *domain.BackendPool, servers []*domain.BackendServer) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("pool create tx begin: %v", err)
	}
	defer tx.Rollback()

	hcType, hcConfig := marshalHealthCheck(p.HealthCheckConf)
	res, err := tx.ExecContext(ctx,
		`INSERT INTO backend_pools (name, description, algorithm, timeout_connect, timeout_server,
		      health_check, health_check_type, health_check_config,
		      protocol, ssl_mode, forward_headers)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Description, string(p.Algorithm),
		p.TimeoutConnect, p.TimeoutServer,
		boolToInt(p.HealthCheckConf.IsEnabled()), hcType, hcConfig,
		string(p.Protocol), string(p.SSLMode), boolToInt(p.ForwardHeaders))
	if err != nil {
		return 0, fmt.Errorf("pool create tx: %v", err)
	}
	poolID, _ := res.LastInsertId()

	for _, s := range servers {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO backend_servers (id_backend_pools, name, ip_address, port, weight, backup, enabled)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			int(poolID), s.Name, s.IPAddress, s.Port,
			s.Weight, boolToInt(s.Backup), boolToInt(s.Enabled))
		if err != nil {
			return 0, fmt.Errorf("server create tx (server %s): %v", s.Name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("pool create tx commit: %v", err)
	}
	return int(poolID), nil
}

func (r *BackendRepository) UpdatePool(ctx context.Context, p *domain.BackendPool) error {
	hcType, hcConfig := marshalHealthCheck(p.HealthCheckConf)
	q := `UPDATE backend_pools SET name=?, description=?, algorithm=?,
	             timeout_connect=?, timeout_server=?, health_check=?,
	             health_check_type=?, health_check_config=?,
	             protocol=?, ssl_mode=?, forward_headers=?,
	             timestamp=CURRENT_TIMESTAMP
	      WHERE id_backend_pools=?`
	_, err := r.db.ExecContext(ctx, q,
		p.Name, p.Description, string(p.Algorithm),
		p.TimeoutConnect, p.TimeoutServer,
		boolToInt(p.HealthCheckConf.IsEnabled()),
		hcType, hcConfig,
		string(p.Protocol), string(p.SSLMode), boolToInt(p.ForwardHeaders),
		p.ID)
	return err
}

func (r *BackendRepository) DeletePool(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM backend_pools WHERE id_backend_pools=?", id)
	return err
}

// ─── Server ───────────────────────────────────────────────────────────────────

// ReplaceServers mengganti semua server di pool secara atomik dalam satu transaksi.
// Server lama dihapus, server baru diinsert. Jika ada yang gagal, rollback ke kondisi semula.
func (r *BackendRepository) ReplaceServers(ctx context.Context, poolID int, servers []*domain.BackendServer) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("replace servers tx begin: %v", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM backend_servers WHERE id_backend_pools=?", poolID); err != nil {
		return fmt.Errorf("replace servers delete: %v", err)
	}

	for _, s := range servers {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO backend_servers (id_backend_pools, name, ip_address, port, weight, backup, enabled)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			poolID, s.Name, s.IPAddress, s.Port,
			s.Weight, boolToInt(s.Backup), boolToInt(s.Enabled))
		if err != nil {
			return fmt.Errorf("replace servers insert (server %s): %v", s.Name, err)
		}
	}

	return tx.Commit()
}

// ─── internal helpers ─────────────────────────────────────────────────────────

func (r *BackendRepository) listServers(ctx context.Context, poolID int) ([]domain.BackendServer, error) {
	q := `SELECT id_backend_servers, id_backend_pools, name, ip_address, port,
	             weight, backup, enabled, created, timestamp
	      FROM backend_servers WHERE id_backend_pools=? ORDER BY name ASC`
	rows, err := r.db.QueryContext(ctx, q, poolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var servers []domain.BackendServer
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		servers = append(servers, *s)
	}
	return servers, rows.Err()
}

func scanPool(s scanner) (*domain.BackendPool, error) {
	var p domain.BackendPool
	var desc sql.NullString
	var healthCheck, forwardHeaders int
	var hcType, hcConfig, protocol, sslMode sql.NullString
	err := s.Scan(
		&p.ID, &p.Name, &desc, &p.Algorithm,
		&p.TimeoutConnect, &p.TimeoutServer, &healthCheck,
		&hcType, &hcConfig, &protocol, &sslMode, &forwardHeaders,
		&p.Created, &p.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("backend pool tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan pool: %v", err)
	}
	p.Description = desc.String
	p.HealthCheckConf = unmarshalHealthCheck(hcType.String, hcConfig.String)
	p.HealthCheck = p.HealthCheckConf.IsEnabled()

	p.Protocol = domain.BackendProtocol(protocol.String)
	if p.Protocol == "" {
		p.Protocol = domain.BackendProtocolHTTP
	}
	p.SSLMode = domain.BackendSSLMode(sslMode.String)
	if p.SSLMode == "" {
		p.SSLMode = domain.BackendSSLModeNone
	}
	p.ForwardHeaders = forwardHeaders == 1
	return &p, nil
}

// marshalHealthCheck mengkonversi HealthCheckConfig ke dua nilai DB: type string dan params JSON
func marshalHealthCheck(cfg domain.HealthCheckConfig) (string, string) {
	hcType := string(cfg.Type)
	if hcType == "" {
		hcType = string(domain.HealthCheckNone)
	}
	// Simpan hanya params (bukan type, sudah ada kolom tersendiri)
	type params struct {
		Path   string `json:"path,omitempty"`
		Expect string `json:"expect,omitempty"`
		User   string `json:"user,omitempty"`
		Custom string `json:"custom,omitempty"`
	}
	p := params{Path: cfg.Path, Expect: cfg.Expect, User: cfg.User, Custom: cfg.Custom}
	b, _ := json.Marshal(p)
	return hcType, string(b)
}

// unmarshalHealthCheck merekonstruksi HealthCheckConfig dari dua nilai DB
func unmarshalHealthCheck(hcType, hcConfigJSON string) domain.HealthCheckConfig {
	cfg := domain.HealthCheckConfig{Type: domain.HealthCheckType(hcType)}
	if hcConfigJSON != "" && hcConfigJSON != "{}" {
		// Unmarshal hanya params, type diset dari kolom tersendiri
		_ = json.Unmarshal([]byte(hcConfigJSON), &cfg)
		cfg.Type = domain.HealthCheckType(hcType) // restore (json.Unmarshal mungkin override)
	}
	return cfg
}

func scanServer(s scanner) (*domain.BackendServer, error) {
	var sv domain.BackendServer
	var backup, enabled int
	err := s.Scan(
		&sv.ID, &sv.BackendPoolID, &sv.Name, &sv.IPAddress, &sv.Port,
		&sv.Weight, &backup, &enabled, &sv.Created, &sv.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("backend server tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan server: %v", err)
	}
	sv.Backup = backup == 1
	sv.Enabled = enabled == 1
	return &sv, nil
}

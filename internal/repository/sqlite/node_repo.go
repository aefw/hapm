package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
)

// NodeRepository adalah implementasi SQLite untuk domain.NodeRepository
type NodeRepository struct{ db *sql.DB }

func NewNodeRepository(db *sql.DB) *NodeRepository {
	return &NodeRepository{db: db}
}

const nodeSelectCols = `SELECT id_nodes, name, hostname, ip_address, ssh_port, ssh_user,
       ssh_private_key, description, status, last_checked, haproxy_version,
       behind_cloudflare, https_frontend_enabled, created, timestamp FROM nodes`

func (r *NodeRepository) FindByID(ctx context.Context, id int) (*domain.Node, error) {
	return scanNode(r.db.QueryRowContext(ctx, nodeSelectCols+` WHERE id_nodes=? LIMIT 1`, id))
}

func (r *NodeRepository) FindByName(ctx context.Context, name string) (*domain.Node, error) {
	return scanNode(r.db.QueryRowContext(ctx, nodeSelectCols+` WHERE name=? LIMIT 1`, name))
}

func (r *NodeRepository) List(ctx context.Context, f domain.ListFilter) ([]*domain.Node, int, error) {
	base := `FROM nodes`
	var args []interface{}

	if f.Q != "" {
		like := "%" + f.Q + "%"
		base += ` WHERE (name LIKE ? OR hostname LIKE ? OR ip_address LIKE ? OR description LIKE ?)`
		args = append(args, like, like, like, like)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// nodeSelectCols sudah berisi "SELECT ... FROM nodes", jadi kita ganti FROM-nya
	selectCols := `SELECT id_nodes, name, hostname, ip_address, ssh_port, ssh_user,
	       ssh_private_key, description, status, last_checked, haproxy_version,
	       behind_cloudflare, https_frontend_enabled, created, timestamp ` + base + ` ORDER BY name ASC`
	qArgs := append([]interface{}{}, args...)
	if f.Limit > 0 {
		selectCols += " LIMIT ? OFFSET ?"
		qArgs = append(qArgs, f.Limit, f.Start)
	}

	rows, err := r.db.QueryContext(ctx, selectCols, qArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var nodes []*domain.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, 0, err
		}
		nodes = append(nodes, n)
	}
	return nodes, total, rows.Err()
}

func (r *NodeRepository) Create(ctx context.Context, n *domain.Node) (int, error) {
	q := `INSERT INTO nodes (name, hostname, ip_address, ssh_port, ssh_user,
	             ssh_private_key, description, behind_cloudflare, https_frontend_enabled)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q,
		n.Name, n.Hostname, n.IPAddress, n.SSHPort, n.SSHUser,
		n.SSHPrivateKey, n.Description, boolToInt(n.BehindCloudflare), boolToInt(n.HTTPSFrontendEnabled))
	if err != nil {
		return 0, fmt.Errorf("node create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *NodeRepository) Update(ctx context.Context, n *domain.Node) error {
	q := `UPDATE nodes SET name=?, hostname=?, ip_address=?, ssh_port=?, ssh_user=?,
	             ssh_private_key=?, description=?, behind_cloudflare=?,
	             https_frontend_enabled=?, timestamp=CURRENT_TIMESTAMP
	      WHERE id_nodes=?`
	_, err := r.db.ExecContext(ctx, q,
		n.Name, n.Hostname, n.IPAddress, n.SSHPort, n.SSHUser,
		n.SSHPrivateKey, n.Description, boolToInt(n.BehindCloudflare),
		boolToInt(n.HTTPSFrontendEnabled), n.ID)
	return err
}

func (r *NodeRepository) Delete(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM nodes WHERE id_nodes=?", id)
	return err
}

func (r *NodeRepository) UpdateStatus(ctx context.Context, id int, status domain.NodeStatus, version string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE nodes SET status=?, haproxy_version=?, last_checked=CURRENT_TIMESTAMP,
		 timestamp=CURRENT_TIMESTAMP WHERE id_nodes=?`,
		string(status), version, id)
	return err
}

func scanNode(s scanner) (*domain.Node, error) {
	var n domain.Node
	var key, desc, lastChecked, version sql.NullString
	var behindCloudflare, httpsFrontendEnabled int
	err := s.Scan(
		&n.ID, &n.Name, &n.Hostname, &n.IPAddress, &n.SSHPort, &n.SSHUser,
		&key, &desc, &n.Status, &lastChecked, &version,
		&behindCloudflare, &httpsFrontendEnabled, &n.Created, &n.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("node tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan node: %v", err)
	}
	n.SSHPrivateKey = key.String
	n.Description = desc.String
	n.HAProxyVersion = version.String
	n.BehindCloudflare = behindCloudflare == 1
	n.HTTPSFrontendEnabled = httpsFrontendEnabled == 1
	return &n, nil
}

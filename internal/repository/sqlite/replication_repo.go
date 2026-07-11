package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/aefw/hapm/internal/domain"
)

// ReplicationRepository adalah implementasi SQLite untuk domain.ReplicationRepository
type ReplicationRepository struct{ db *sql.DB }

func NewReplicationRepository(db *sql.DB) *ReplicationRepository {
	return &ReplicationRepository{db: db}
}

// ─── Targets ─────────────────────────────────────────────────────────────────

func (r *ReplicationRepository) FindTargetByID(ctx context.Context, id int) (*domain.ReplicationTarget, error) {
	q := `SELECT rt.id_replication_targets, rt.id_nodes_source, ns.name,
	             rt.id_nodes_target, nt.name,
	             rt.sync_frontends, rt.sync_backends, rt.sync_ssl, rt.sync_maps,
	             rt.enabled, rt.created, rt.timestamp
	      FROM replication_targets rt
	      LEFT JOIN nodes ns ON ns.id_nodes = rt.id_nodes_source
	      LEFT JOIN nodes nt ON nt.id_nodes = rt.id_nodes_target
	      WHERE rt.id_replication_targets=? LIMIT 1`
	return scanReplicationTarget(r.db.QueryRowContext(ctx, q, id))
}

func (r *ReplicationRepository) ListTargets(ctx context.Context) ([]*domain.ReplicationTarget, error) {
	q := `SELECT rt.id_replication_targets, rt.id_nodes_source, ns.name,
	             rt.id_nodes_target, nt.name,
	             rt.sync_frontends, rt.sync_backends, rt.sync_ssl, rt.sync_maps,
	             rt.enabled, rt.created, rt.timestamp
	      FROM replication_targets rt
	      LEFT JOIN nodes ns ON ns.id_nodes = rt.id_nodes_source
	      LEFT JOIN nodes nt ON nt.id_nodes = rt.id_nodes_target
	      ORDER BY rt.created DESC`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []*domain.ReplicationTarget
	for rows.Next() {
		t, err := scanReplicationTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

func (r *ReplicationRepository) ListTargetsBySource(ctx context.Context, sourceNodeID int) ([]*domain.ReplicationTarget, error) {
	q := `SELECT rt.id_replication_targets, rt.id_nodes_source, ns.name,
	             rt.id_nodes_target, nt.name,
	             rt.sync_frontends, rt.sync_backends, rt.sync_ssl, rt.sync_maps,
	             rt.enabled, rt.created, rt.timestamp
	      FROM replication_targets rt
	      LEFT JOIN nodes ns ON ns.id_nodes = rt.id_nodes_source
	      LEFT JOIN nodes nt ON nt.id_nodes = rt.id_nodes_target
	      WHERE rt.id_nodes_source=? AND rt.enabled=1
	      ORDER BY rt.created ASC`
	rows, err := r.db.QueryContext(ctx, q, sourceNodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []*domain.ReplicationTarget
	for rows.Next() {
		t, err := scanReplicationTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

func (r *ReplicationRepository) CreateTarget(ctx context.Context, t *domain.ReplicationTarget) (int, error) {
	q := `INSERT INTO replication_targets
	      (id_nodes_source, id_nodes_target, sync_frontends, sync_backends, sync_ssl, sync_maps, enabled)
	      VALUES (?, ?, ?, ?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q,
		t.SourceNodeID, t.TargetNodeID,
		boolToInt(t.SyncFrontends), boolToInt(t.SyncBackends),
		boolToInt(t.SyncSSL), boolToInt(t.SyncMaps), boolToInt(t.Enabled))
	if err != nil {
		return 0, fmt.Errorf("replication target create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *ReplicationRepository) UpdateTarget(ctx context.Context, t *domain.ReplicationTarget) error {
	q := `UPDATE replication_targets SET
	             id_nodes_source=?, id_nodes_target=?,
	             sync_frontends=?, sync_backends=?, sync_ssl=?, sync_maps=?,
	             enabled=?, timestamp=CURRENT_TIMESTAMP
	      WHERE id_replication_targets=?`
	_, err := r.db.ExecContext(ctx, q,
		t.SourceNodeID, t.TargetNodeID,
		boolToInt(t.SyncFrontends), boolToInt(t.SyncBackends),
		boolToInt(t.SyncSSL), boolToInt(t.SyncMaps), boolToInt(t.Enabled), t.ID)
	return err
}

func (r *ReplicationRepository) DeleteTarget(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM replication_targets WHERE id_replication_targets=?", id)
	return err
}

// ─── Jobs ─────────────────────────────────────────────────────────────────────

func (r *ReplicationRepository) CreateJob(ctx context.Context, j *domain.ReplicationJob) (int, error) {
	q := `INSERT INTO replication_jobs (id_replication_targets, id_users, status, started_at)
	      VALUES (?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q, j.ReplicationID, j.UserID, j.Status, time.Now())
	if err != nil {
		return 0, fmt.Errorf("replication job create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *ReplicationRepository) UpdateJobStatus(ctx context.Context, id int, status string, errMsg string) error {
	q := `UPDATE replication_jobs SET status=?, error_message=?,
	             finished_at=CASE WHEN ? IN ('success','failed') THEN CURRENT_TIMESTAMP ELSE finished_at END,
	             timestamp=CURRENT_TIMESTAMP
	      WHERE id_replication_jobs=?`
	_, err := r.db.ExecContext(ctx, q, status, errMsg, status, id)
	return err
}

// ─── Drift ────────────────────────────────────────────────────────────────────

// DriftRepository adalah implementasi SQLite untuk domain.DriftRepository
type DriftRepository struct{ db *sql.DB }

func NewDriftRepository(db *sql.DB) *DriftRepository {
	return &DriftRepository{db: db}
}

func (r *DriftRepository) Create(ctx context.Context, rpt *domain.DriftReport) (int, error) {
	q := `INSERT INTO drift_reports (id_nodes, live_config_hash, db_config_hash, drift_detected, checked_at)
	      VALUES (?, ?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q,
		rpt.NodeID, rpt.LiveConfigHash, rpt.DBConfigHash,
		boolToInt(rpt.DriftDetected), rpt.CheckedAt)
	if err != nil {
		return 0, fmt.Errorf("drift create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *DriftRepository) LatestByNode(ctx context.Context, nodeID int) (*domain.DriftReport, error) {
	q := `SELECT dr.id_drift_reports, dr.id_nodes, n.name,
	             dr.live_config_hash, dr.db_config_hash, dr.drift_detected,
	             dr.checked_at, dr.created
	      FROM drift_reports dr
	      LEFT JOIN nodes n USING(id_nodes)
	      WHERE dr.id_nodes=? ORDER BY dr.checked_at DESC LIMIT 1`
	return scanDriftReport(r.db.QueryRowContext(ctx, q, nodeID))
}

func (r *DriftRepository) ListRecent(ctx context.Context, limit int) ([]*domain.DriftReport, error) {
	q := `SELECT dr.id_drift_reports, dr.id_nodes, n.name,
	             dr.live_config_hash, dr.db_config_hash, dr.drift_detected,
	             dr.checked_at, dr.created
	      FROM drift_reports dr
	      LEFT JOIN nodes n USING(id_nodes)
	      ORDER BY dr.checked_at DESC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []*domain.DriftReport
	for rows.Next() {
		rpt, err := scanDriftReport(rows)
		if err != nil {
			return nil, err
		}
		reports = append(reports, rpt)
	}
	return reports, rows.Err()
}

// ─── Audit ────────────────────────────────────────────────────────────────────

// AuditRepository adalah implementasi SQLite untuk domain.AuditRepository
type AuditRepository struct{ db *sql.DB }

func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Create(ctx context.Context, l *domain.AuditLog) error {
	q := `INSERT INTO audit_logs (id_users, action, resource_type, resource_id, detail, ip_address, user_agent)
	      VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, q,
		l.UserID, l.Action, l.ResourceType, l.ResourceID,
		l.Detail, l.IPAddress, l.UserAgent)
	return err
}

func (r *AuditRepository) FindByID(ctx context.Context, id int) (*domain.AuditLog, error) {
	q := `SELECT al.id_audit_logs, al.id_users, u.username, al.action,
	             al.resource_type, al.resource_id, al.detail,
	             al.ip_address, al.user_agent, al.created
	      FROM audit_logs al
	      LEFT JOIN users u USING(id_users)
	      WHERE al.id_audit_logs=? LIMIT 1`
	return scanAuditLog(r.db.QueryRowContext(ctx, q, id))
}

func (r *AuditRepository) List(ctx context.Context, f domain.AuditFilter) ([]*domain.AuditLog, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}

	if f.Q != "" {
		like := "%" + f.Q + "%"
		where += " AND (al.action LIKE ? OR al.resource_type LIKE ? OR al.detail LIKE ?)"
		args = append(args, like, like, like)
	}
	if f.UserID != nil {
		where += " AND al.id_users=?"
		args = append(args, *f.UserID)
	}
	if f.Action != "" {
		where += " AND al.action=?"
		args = append(args, f.Action)
	}
	if f.ResourceType != "" {
		where += " AND al.resource_type=?"
		args = append(args, f.ResourceType)
	}
	if f.ResourceID != nil {
		where += " AND al.resource_id=?"
		args = append(args, *f.ResourceID)
	}
	if f.FromDate != nil {
		where += " AND al.created >= ?"
		args = append(args, f.FromDate)
	}
	if f.ToDate != nil {
		where += " AND al.created <= ?"
		args = append(args, f.ToDate)
	}

	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs al "+where, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	start := f.Start
	if start < 0 {
		start = 0
	}

	q := `SELECT al.id_audit_logs, al.id_users, u.username, al.action,
	             al.resource_type, al.resource_id, al.detail,
	             al.ip_address, al.user_agent, al.created
	      FROM audit_logs al
	      LEFT JOIN users u USING(id_users)
	      ` + where + ` ORDER BY al.created DESC LIMIT ? OFFSET ?`
	args = append(args, limit, start)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		l, err := scanAuditLog(rows)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}

// ─── Scan helpers ─────────────────────────────────────────────────────────────

func scanReplicationTarget(s scanner) (*domain.ReplicationTarget, error) {
	var t domain.ReplicationTarget
	var srcName, tgtName sql.NullString
	var syncF, syncB, syncS, syncM, enabled int
	err := s.Scan(
		&t.ID, &t.SourceNodeID, &srcName,
		&t.TargetNodeID, &tgtName,
		&syncF, &syncB, &syncS, &syncM,
		&enabled, &t.Created, &t.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("replication target tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan replication target: %v", err)
	}
	t.SourceNodeName = srcName.String
	t.TargetNodeName = tgtName.String
	t.SyncFrontends = syncF == 1
	t.SyncBackends = syncB == 1
	t.SyncSSL = syncS == 1
	t.SyncMaps = syncM == 1
	t.Enabled = enabled == 1
	return &t, nil
}

func scanDriftReport(s scanner) (*domain.DriftReport, error) {
	var r domain.DriftReport
	var nodeName sql.NullString
	var driftDetected int
	err := s.Scan(
		&r.ID, &r.NodeID, &nodeName,
		&r.LiveConfigHash, &r.DBConfigHash, &driftDetected,
		&r.CheckedAt, &r.Created,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("drift report tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan drift report: %v", err)
	}
	r.NodeName = nodeName.String
	r.DriftDetected = driftDetected == 1
	return &r, nil
}

func scanAuditLog(s scanner) (*domain.AuditLog, error) {
	var l domain.AuditLog
	var userID sql.NullInt64
	var username, resourceType, detail, ipAddr, userAgent sql.NullString
	var resourceID sql.NullInt64
	err := s.Scan(
		&l.ID, &userID, &username, &l.Action,
		&resourceType, &resourceID, &detail,
		&ipAddr, &userAgent, &l.Created,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("audit log tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan audit log: %v", err)
	}
	if userID.Valid {
		id := int(userID.Int64)
		l.UserID = &id
	}
	l.Username = username.String
	l.ResourceType = resourceType.String
	if resourceID.Valid {
		id := int(resourceID.Int64)
		l.ResourceID = &id
	}
	l.Detail = detail.String
	l.IPAddress = ipAddr.String
	l.UserAgent = userAgent.String
	return &l, nil
}

package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
)

// DeploymentRepository adalah implementasi SQLite untuk domain.DeploymentRepository
type DeploymentRepository struct{ db *sql.DB }

func NewDeploymentRepository(db *sql.DB) *DeploymentRepository {
	return &DeploymentRepository{db: db}
}

func (r *DeploymentRepository) FindByID(ctx context.Context, id int) (*domain.Deployment, error) {
	q := `SELECT d.id_deployments, d.id_nodes, n.name, d.id_config_revisions,
	             cr.revision_number, d.id_users, u.username,
	             d.status, d.stage, d.error_message,
	             d.started_at, d.finished_at, d.created, d.timestamp
	      FROM deployments d
	      LEFT JOIN nodes n USING(id_nodes)
	      LEFT JOIN config_revisions cr USING(id_config_revisions)
	      LEFT JOIN users u USING(id_users)
	      WHERE d.id_deployments=? LIMIT 1`
	return scanDeployment(r.db.QueryRowContext(ctx, q, id))
}

func (r *DeploymentRepository) ListByNode(ctx context.Context, nodeID int, limit int) ([]*domain.Deployment, error) {
	q := `SELECT d.id_deployments, d.id_nodes, n.name, d.id_config_revisions,
	             cr.revision_number, d.id_users, u.username,
	             d.status, d.stage, d.error_message,
	             d.started_at, d.finished_at, d.created, d.timestamp
	      FROM deployments d
	      LEFT JOIN nodes n USING(id_nodes)
	      LEFT JOIN config_revisions cr USING(id_config_revisions)
	      LEFT JOIN users u USING(id_users)
	      WHERE d.id_nodes=?
	      ORDER BY d.created DESC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, q, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var deployments []*domain.Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		deployments = append(deployments, d)
	}
	return deployments, rows.Err()
}

func (r *DeploymentRepository) ListRecent(ctx context.Context, limit int) ([]*domain.Deployment, error) {
	q := `SELECT d.id_deployments, d.id_nodes, n.name, d.id_config_revisions,
	             cr.revision_number, d.id_users, u.username,
	             d.status, d.stage, d.error_message,
	             d.started_at, d.finished_at, d.created, d.timestamp
	      FROM deployments d
	      LEFT JOIN nodes n USING(id_nodes)
	      LEFT JOIN config_revisions cr USING(id_config_revisions)
	      LEFT JOIN users u USING(id_users)
	      ORDER BY d.created DESC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var deployments []*domain.Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		deployments = append(deployments, d)
	}
	return deployments, rows.Err()
}

func (r *DeploymentRepository) Create(ctx context.Context, d *domain.Deployment) (int, error) {
	q := `INSERT INTO deployments (id_nodes, id_config_revisions, id_users, status, stage, started_at)
	      VALUES (?, ?, ?, ?, ?, ?)`
	// id_config_revisions nullable — NULL saat deployment dimulai sebelum revision tersimpan
	var revID sql.NullInt64
	if d.RevisionID > 0 {
		revID = sql.NullInt64{Int64: int64(d.RevisionID), Valid: true}
	}
	res, err := r.db.ExecContext(ctx, q,
		d.NodeID, revID, d.UserID,
		string(d.Status), string(d.Stage), d.StartedAt)
	if err != nil {
		return 0, fmt.Errorf("deployment create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *DeploymentRepository) UpdateStatus(ctx context.Context, id int, status domain.DeployStatus, stage domain.DeployStage, errMsg string) error {
	q := `UPDATE deployments SET status=?, stage=?, error_message=?,
	             finished_at=CASE WHEN ? IN ('success','failed','rolled_back') THEN CURRENT_TIMESTAMP ELSE finished_at END,
	             timestamp=CURRENT_TIMESTAMP
	      WHERE id_deployments=?`
	_, err := r.db.ExecContext(ctx, q, string(status), string(stage), errMsg, string(status), id)
	return err
}

func scanDeployment(s scanner) (*domain.Deployment, error) {
	var d domain.Deployment
	var nodeName, username sql.NullString
	// id_config_revisions nullable (NULL saat deployment baru dimulai sebelum revision tersimpan)
	var revisionID, revNumber sql.NullInt64
	var stage, errMsg sql.NullString
	var startedAt, finishedAt sql.NullTime
	err := s.Scan(
		&d.ID, &d.NodeID, &nodeName, &revisionID,
		&revNumber, &d.UserID, &username,
		&d.Status, &stage, &errMsg,
		&startedAt, &finishedAt, &d.Created, &d.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("deployment tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan deployment: %v", err)
	}
	d.NodeName = nodeName.String
	d.Username = username.String
	if revisionID.Valid {
		d.RevisionID = int(revisionID.Int64)
	}
	if revNumber.Valid {
		d.RevisionNumber = int(revNumber.Int64)
	}
	d.Stage = domain.DeployStage(stage.String)
	d.ErrorMessage = errMsg.String
	if startedAt.Valid {
		t := startedAt.Time
		d.StartedAt = &t
	}
	if finishedAt.Valid {
		t := finishedAt.Time
		d.FinishedAt = &t
	}
	return &d, nil
}

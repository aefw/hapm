package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
)

// RevisionRepository adalah implementasi SQLite untuk domain.RevisionRepository
type RevisionRepository struct{ db *sql.DB }

func NewRevisionRepository(db *sql.DB) *RevisionRepository {
	return &RevisionRepository{db: db}
}

func (r *RevisionRepository) FindByID(ctx context.Context, id int) (*domain.ConfigRevision, error) {
	q := `SELECT id_config_revisions, id_nodes, revision_number, config_content,
	             comment, id_users, deployed, created, timestamp
	      FROM config_revisions WHERE id_config_revisions=? LIMIT 1`
	return scanRevision(r.db.QueryRowContext(ctx, q, id))
}

func (r *RevisionRepository) FindByNodeAndNumber(ctx context.Context, nodeID, number int) (*domain.ConfigRevision, error) {
	q := `SELECT id_config_revisions, id_nodes, revision_number, config_content,
	             comment, id_users, deployed, created, timestamp
	      FROM config_revisions WHERE id_nodes=? AND revision_number=? LIMIT 1`
	return scanRevision(r.db.QueryRowContext(ctx, q, nodeID, number))
}

func (r *RevisionRepository) LatestByNode(ctx context.Context, nodeID int) (*domain.ConfigRevision, error) {
	q := `SELECT id_config_revisions, id_nodes, revision_number, config_content,
	             comment, id_users, deployed, created, timestamp
	      FROM config_revisions WHERE id_nodes=? ORDER BY revision_number DESC LIMIT 1`
	return scanRevision(r.db.QueryRowContext(ctx, q, nodeID))
}

func (r *RevisionRepository) ListByNode(ctx context.Context, nodeID int) ([]*domain.ConfigRevisionSummary, error) {
	q := `SELECT cr.id_config_revisions, cr.id_nodes, cr.revision_number,
	             cr.comment, cr.id_users, u.username, cr.deployed, cr.created
	      FROM config_revisions cr
	      LEFT JOIN users u USING(id_users)
	      WHERE cr.id_nodes=?
	      ORDER BY cr.revision_number DESC`
	rows, err := r.db.QueryContext(ctx, q, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var revisions []*domain.ConfigRevisionSummary
	for rows.Next() {
		var s domain.ConfigRevisionSummary
		var comment, username sql.NullString
		var deployed int
		if err := rows.Scan(
			&s.ID, &s.NodeID, &s.RevisionNumber,
			&comment, &s.UserID, &username, &deployed, &s.Created,
		); err != nil {
			return nil, fmt.Errorf("scan revision summary: %v", err)
		}
		s.Comment = comment.String
		s.Username = username.String
		s.Deployed = deployed == 1
		revisions = append(revisions, &s)
	}
	return revisions, rows.Err()
}

func (r *RevisionRepository) Create(ctx context.Context, rev *domain.ConfigRevision) (int, error) {
	q := `INSERT INTO config_revisions (id_nodes, revision_number, config_content, comment, id_users)
	      VALUES (?, ?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q,
		rev.NodeID, rev.RevisionNumber, rev.ConfigContent, rev.Comment, rev.UserID)
	if err != nil {
		return 0, fmt.Errorf("revision create: %v", err)
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func (r *RevisionRepository) MarkDeployed(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE config_revisions SET deployed=1, timestamp=CURRENT_TIMESTAMP WHERE id_config_revisions=?", id)
	return err
}

func (r *RevisionRepository) NextRevisionNumber(ctx context.Context, nodeID int) (int, error) {
	var max sql.NullInt64
	err := r.db.QueryRowContext(ctx,
		"SELECT MAX(revision_number) FROM config_revisions WHERE id_nodes=?", nodeID,
	).Scan(&max)
	if err != nil {
		return 0, err
	}
	if !max.Valid {
		return 1, nil
	}
	return int(max.Int64) + 1, nil
}

func scanRevision(s scanner) (*domain.ConfigRevision, error) {
	var r domain.ConfigRevision
	var comment sql.NullString
	var deployed int
	err := s.Scan(
		&r.ID, &r.NodeID, &r.RevisionNumber, &r.ConfigContent,
		&comment, &r.UserID, &deployed, &r.Created, &r.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("revision tidak ditemukan")
	}
	if err != nil {
		return nil, fmt.Errorf("scan revision: %v", err)
	}
	r.Comment = comment.String
	r.Deployed = deployed == 1
	return &r, nil
}

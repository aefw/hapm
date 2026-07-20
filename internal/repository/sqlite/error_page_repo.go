package sqlite

import (
	"context"
	"database/sql"

	"github.com/aefw/hapm/internal/domain"
)

type errorPageRepo struct{ db *sql.DB }

func NewErrorPageRepository(db *sql.DB) domain.ErrorPageRepository {
	return &errorPageRepo{db: db}
}

func (r *errorPageRepo) List(ctx context.Context) ([]*domain.ErrorPage, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id_error_pages, error_code, content, enabled, created, timestamp
		 FROM error_pages ORDER BY error_code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*domain.ErrorPage
	for rows.Next() {
		ep := &domain.ErrorPage{}
		var enabled int
		if err := rows.Scan(&ep.ID, &ep.ErrorCode, &ep.Content, &enabled, &ep.Created, &ep.Timestamp); err != nil {
			return nil, err
		}
		ep.Enabled = enabled == 1
		list = append(list, ep)
	}
	return list, rows.Err()
}

func (r *errorPageRepo) FindByCode(ctx context.Context, code int) (*domain.ErrorPage, error) {
	ep := &domain.ErrorPage{}
	var enabled int
	err := r.db.QueryRowContext(ctx,
		`SELECT id_error_pages, error_code, content, enabled, created, timestamp
		 FROM error_pages WHERE error_code = ?`, code).
		Scan(&ep.ID, &ep.ErrorCode, &ep.Content, &enabled, &ep.Created, &ep.Timestamp)
	if err != nil {
		return nil, err
	}
	ep.Enabled = enabled == 1
	return ep, nil
}

func (r *errorPageRepo) Update(ctx context.Context, ep *domain.ErrorPage) error {
	enabled := 0
	if ep.Enabled {
		enabled = 1
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE error_pages SET content = ?, enabled = ?, timestamp = CURRENT_TIMESTAMP WHERE error_code = ?`,
		ep.Content, enabled, ep.ErrorCode)
	return err
}

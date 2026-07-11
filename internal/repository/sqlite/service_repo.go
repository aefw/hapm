package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
)

// ServiceRepository adalah implementasi SQLite untuk domain.ServiceRepository
type ServiceRepository struct{ db *sql.DB }

// NewServiceRepository membuat instance ServiceRepository baru
func NewServiceRepository(db *sql.DB) *ServiceRepository {
	return &ServiceRepository{db: db}
}

const serviceSelectCols = `
    SELECT s.id_services, s.name, s.service_type, s.listen_port, s.id_backend_pools,
           s.description, s.enabled, s.created, s.timestamp,
           bp.id_backend_pools, bp.name, bp.description, bp.algorithm,
           bp.timeout_connect, bp.timeout_server, bp.health_check,
           bp.health_check_type, bp.health_check_config, bp.created, bp.timestamp
    FROM services s
    LEFT JOIN backend_pools bp ON bp.id_backend_pools = s.id_backend_pools`

func scanService(row scanner) (*domain.Service, error) {
	s := &domain.Service{}
	var (
		enabled     int
		bpID        sql.NullInt64
		bpName      sql.NullString
		bpDesc      sql.NullString
		bpAlgo      sql.NullString
		bpTCon      sql.NullInt64
		bpTSrv      sql.NullInt64
		bpHC        sql.NullInt64
		bpHCType    sql.NullString
		bpHCConfig  sql.NullString
		bpCreated   sql.NullTime
		bpTimestamp sql.NullTime
	)
	err := row.Scan(
		&s.ID, &s.Name, &s.ServiceType, &s.ListenPort, &s.BackendPoolID,
		&s.Description, &enabled, &s.Created, &s.Timestamp,
		&bpID, &bpName, &bpDesc, &bpAlgo,
		&bpTCon, &bpTSrv, &bpHC,
		&bpHCType, &bpHCConfig, &bpCreated, &bpTimestamp,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("service tidak ditemukan")
	}
	if err != nil {
		return nil, err
	}
	s.Enabled = enabled == 1

	if bpID.Valid {
		hcConf := unmarshalHealthCheck(bpHCType.String, bpHCConfig.String)
		s.BackendPool = &domain.BackendPool{
			ID:              int(bpID.Int64),
			Name:            bpName.String,
			Description:     bpDesc.String,
			Algorithm:       domain.Algorithm(bpAlgo.String),
			TimeoutConnect:  int(bpTCon.Int64),
			TimeoutServer:   int(bpTSrv.Int64),
			HealthCheck:     hcConf.IsEnabled(),
			HealthCheckConf: hcConf,
			Created:         bpCreated.Time,
			Timestamp:       bpTimestamp.Time,
		}
	}
	return s, nil
}

func (r *ServiceRepository) FindByID(ctx context.Context, id int) (*domain.Service, error) {
	q := serviceSelectCols + ` WHERE s.id_services = ? LIMIT 1`
	return scanService(r.db.QueryRowContext(ctx, q, id))
}

func (r *ServiceRepository) FindByName(ctx context.Context, name string) (*domain.Service, error) {
	q := serviceSelectCols + ` WHERE s.name = ? LIMIT 1`
	return scanService(r.db.QueryRowContext(ctx, q, name))
}

func (r *ServiceRepository) FindByPort(ctx context.Context, port int) (*domain.Service, error) {
	q := serviceSelectCols + ` WHERE s.listen_port = ? LIMIT 1`
	return scanService(r.db.QueryRowContext(ctx, q, port))
}

func (r *ServiceRepository) List(ctx context.Context, f domain.ListFilter) ([]*domain.Service, int, error) {
	where := ""
	var args []interface{}

	if f.Q != "" {
		like := "%" + f.Q + "%"
		where = ` WHERE (s.name LIKE ? OR s.description LIKE ?)`
		args = append(args, like, like)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM services s"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := serviceSelectCols + where + ` ORDER BY s.name ASC`
	qArgs := append([]interface{}{}, args...)
	if f.Limit > 0 {
		q += " LIMIT ? OFFSET ?"
		qArgs = append(qArgs, f.Limit, f.Start)
	}

	items, err := r.queryServices(ctx, q, qArgs...)
	return items, total, err
}

func (r *ServiceRepository) ListEnabled(ctx context.Context) ([]*domain.Service, error) {
	q := serviceSelectCols + ` WHERE s.enabled = 1 ORDER BY s.name ASC`
	return r.queryServices(ctx, q)
}

func (r *ServiceRepository) queryServices(ctx context.Context, q string, args ...any) ([]*domain.Service, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*domain.Service
	for rows.Next() {
		s, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r *ServiceRepository) Create(ctx context.Context, s *domain.Service) (int, error) {
	enabled := 0
	if s.Enabled {
		enabled = 1
	}
	q := `INSERT INTO services (name, service_type, listen_port, id_backend_pools, description, enabled)
          VALUES (?, ?, ?, ?, ?, ?)`
	res, err := r.db.ExecContext(ctx, q,
		s.Name, string(s.ServiceType), s.ListenPort, s.BackendPoolID, s.Description, enabled)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	return int(id), err
}

func (r *ServiceRepository) Update(ctx context.Context, s *domain.Service) error {
	enabled := 0
	if s.Enabled {
		enabled = 1
	}
	q := `UPDATE services SET name=?, service_type=?, listen_port=?, id_backend_pools=?,
          description=?, enabled=?, timestamp=CURRENT_TIMESTAMP
          WHERE id_services=?`
	_, err := r.db.ExecContext(ctx, q,
		s.Name, string(s.ServiceType), s.ListenPort, s.BackendPoolID,
		s.Description, enabled, s.ID)
	return err
}

func (r *ServiceRepository) Delete(ctx context.Context, id int) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM services WHERE id_services=?`, id)
	return err
}

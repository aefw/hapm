package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aefw/hapm/internal/domain"
)

// CertificateRepository adalah implementasi SQLite untuk domain.CertificateRepository
type CertificateRepository struct{ db *sql.DB }

func NewCertificateRepository(db *sql.DB) *CertificateRepository {
	return &CertificateRepository{db: db}
}

const certSelectCols = `
	SELECT uuid, name, provider, challenge, status, primary_domain,
	       domains, san, zone, dns_provider,
	       issued_at, expires_at, renew_before, auto_renew,
	       fingerprint, error_message, created, timestamp
	FROM certificate_storage`

func (r *CertificateRepository) FindByUUID(ctx context.Context, uuid string) (*domain.Certificate, error) {
	row := r.db.QueryRowContext(ctx, certSelectCols+` WHERE uuid=? LIMIT 1`, uuid)
	c, err := scanCert(row)
	if err != nil {
		return nil, fmt.Errorf("certificate tidak ditemukan: %w", err)
	}
	return c, nil
}

func (r *CertificateRepository) FindByName(ctx context.Context, name string) (*domain.Certificate, error) {
	row := r.db.QueryRowContext(ctx, certSelectCols+` WHERE name=? LIMIT 1`, name)
	c, err := scanCert(row)
	if err != nil {
		return nil, fmt.Errorf("certificate tidak ditemukan: %w", err)
	}
	return c, nil
}

func (r *CertificateRepository) List(ctx context.Context, f domain.ListFilter) ([]*domain.Certificate, int, error) {
	base := `FROM certificate_storage`
	var args []interface{}
	if f.Q != "" {
		like := "%" + f.Q + "%"
		base += ` WHERE (name LIKE ? OR primary_domain LIKE ? OR status LIKE ?)`
		args = append(args, like, like, like)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) "+base, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := `SELECT uuid, name, provider, challenge, status, primary_domain,
	       domains, san, zone, dns_provider,
	       issued_at, expires_at, renew_before, auto_renew,
	       fingerprint, error_message, created, timestamp ` + base +
		` ORDER BY created DESC`
	qArgs := append([]interface{}{}, args...)
	if f.Limit > 0 {
		q += " LIMIT ? OFFSET ?"
		qArgs = append(qArgs, f.Limit, f.Start)
	}

	rows, err := r.db.QueryContext(ctx, q, qArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var certs []*domain.Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, 0, err
		}
		certs = append(certs, c)
	}
	return certs, total, rows.Err()
}

func (r *CertificateRepository) ListNeedingRenewal(ctx context.Context) ([]*domain.Certificate, error) {
	q := certSelectCols + `
		WHERE auto_renew = 1
		  AND status = 'active'
		  AND locked = 0
		  AND expires_at IS NOT NULL
		  AND datetime(expires_at, '-' || renew_before || ' days') <= datetime('now')`

	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*domain.Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

func (r *CertificateRepository) Create(ctx context.Context, c *domain.Certificate) error {
	domainsJSON, _ := json.Marshal(c.Domains)
	sanJSON, _ := json.Marshal(c.SAN)

	q := `INSERT INTO certificate_storage
		(uuid, name, provider, challenge, status, primary_domain,
		 domains, san, zone, dns_provider,
		 issued_at, expires_at, renew_before, auto_renew,
		 fingerprint, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.ExecContext(ctx, q,
		c.UUID, c.Name, string(c.Provider), string(c.Challenge), string(c.Status),
		c.PrimaryDomain, string(domainsJSON), string(sanJSON),
		c.Zone, string(c.DNSProvider),
		timeToSQL(c.IssuedAt), timeToSQL(c.ExpiresAt),
		c.RenewBefore, boolToInt(c.AutoRenew),
		c.Fingerprint, c.ErrorMessage,
	)
	if err != nil {
		return fmt.Errorf("certificate create: %w", err)
	}
	return nil
}

func (r *CertificateRepository) Update(ctx context.Context, c *domain.Certificate) error {
	domainsJSON, _ := json.Marshal(c.Domains)
	sanJSON, _ := json.Marshal(c.SAN)

	q := `UPDATE certificate_storage SET
		name=?, provider=?, challenge=?, status=?, primary_domain=?,
		domains=?, san=?, zone=?, dns_provider=?,
		issued_at=?, expires_at=?, renew_before=?, auto_renew=?,
		fingerprint=?, error_message=?, timestamp=CURRENT_TIMESTAMP
		WHERE uuid=?`

	_, err := r.db.ExecContext(ctx, q,
		c.Name, string(c.Provider), string(c.Challenge), string(c.Status),
		c.PrimaryDomain, string(domainsJSON), string(sanJSON),
		c.Zone, string(c.DNSProvider),
		timeToSQL(c.IssuedAt), timeToSQL(c.ExpiresAt),
		c.RenewBefore, boolToInt(c.AutoRenew),
		c.Fingerprint, c.ErrorMessage,
		c.UUID,
	)
	return err
}

func (r *CertificateRepository) Delete(ctx context.Context, uuid string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM certificate_storage WHERE uuid=?", uuid)
	return err
}

// Lock mencoba mengunci certificate agar tidak diproses ganda (optimistic lock).
// Mengembalikan true jika berhasil dikunci, false jika sudah dikunci proses lain.
func (r *CertificateRepository) Lock(ctx context.Context, uuid string) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		"UPDATE certificate_storage SET locked=1 WHERE uuid=? AND locked=0", uuid)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (r *CertificateRepository) Unlock(ctx context.Context, uuid string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE certificate_storage SET locked=0 WHERE uuid=?", uuid)
	return err
}

func scanCert(s scanner) (*domain.Certificate, error) {
	var c domain.Certificate
	var provider, challenge, status, dnsProvider string
	var domainsJSON, sanJSON string
	var issuedAt, expiresAt sql.NullString
	var autoRenew int

	err := s.Scan(
		&c.UUID, &c.Name, &provider, &challenge, &status, &c.PrimaryDomain,
		&domainsJSON, &sanJSON, &c.Zone, &dnsProvider,
		&issuedAt, &expiresAt, &c.RenewBefore, &autoRenew,
		&c.Fingerprint, &c.ErrorMessage, &c.Created, &c.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("scan certificate: %w", err)
	}

	c.Provider = domain.CertProvider(provider)
	c.Challenge = domain.CertChallenge(challenge)
	c.Status = domain.CertStatus(status)
	c.DNSProvider = domain.DNSProviderType(dnsProvider)
	c.AutoRenew = autoRenew == 1

	if issuedAt.Valid && issuedAt.String != "" {
		if t, ok := parseSQLiteTime(issuedAt.String); ok {
			c.IssuedAt = &t
		}
	}
	if expiresAt.Valid && expiresAt.String != "" {
		if t, ok := parseSQLiteTime(expiresAt.String); ok {
			c.ExpiresAt = &t
		}
	}

	_ = json.Unmarshal([]byte(domainsJSON), &c.Domains)
	_ = json.Unmarshal([]byte(sanJSON), &c.SAN)
	if c.Domains == nil {
		c.Domains = []string{}
	}
	if c.SAN == nil {
		c.SAN = []string{}
	}

	return &c, nil
}

// ─── CertJobRepository ────────────────────────────────────────────────────────

type CertJobRepository struct{ db *sql.DB }

func NewCertJobRepository(db *sql.DB) *CertJobRepository {
	return &CertJobRepository{db: db}
}

func (r *CertJobRepository) FindByUUID(ctx context.Context, uuid string) (*domain.CertJob, error) {
	q := `SELECT uuid, cert_uuid, job_type, status, logs, error_message,
		started_at, finished_at, created, timestamp
		FROM certificate_jobs WHERE uuid=? LIMIT 1`
	row := r.db.QueryRowContext(ctx, q, uuid)
	j, err := scanJob(row)
	if err != nil {
		return nil, fmt.Errorf("job tidak ditemukan")
	}
	return j, nil
}

func (r *CertJobRepository) ListByCert(ctx context.Context, certUUID string, limit int) ([]*domain.CertJob, error) {
	q := `SELECT uuid, cert_uuid, job_type, status, logs, error_message,
		started_at, finished_at, created, timestamp
		FROM certificate_jobs WHERE cert_uuid=? ORDER BY created DESC LIMIT ?`
	return r.queryJobs(ctx, q, certUUID, limit)
}

func (r *CertJobRepository) ListAll(ctx context.Context, limit int) ([]*domain.CertJob, error) {
	q := `SELECT uuid, cert_uuid, job_type, status, logs, error_message,
		started_at, finished_at, created, timestamp
		FROM certificate_jobs ORDER BY created DESC LIMIT ?`
	return r.queryJobs(ctx, q, limit)
}

func (r *CertJobRepository) Create(ctx context.Context, j *domain.CertJob) error {
	q := `INSERT INTO certificate_jobs
		(uuid, cert_uuid, job_type, status, logs, error_message)
		VALUES (?, ?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, q,
		j.UUID, j.CertUUID, j.JobType, j.Status, j.Logs, j.ErrorMsg)
	return err
}

func (r *CertJobRepository) UpdateStatus(ctx context.Context, uuid, status, logs, errMsg string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	var startedAt, finishedAt interface{}

	switch status {
	case domain.JobStatusRunning:
		startedAt = now
	case domain.JobStatusSuccess, domain.JobStatusFailed:
		finishedAt = now
	}

	q := `UPDATE certificate_jobs SET status=?, logs=?, error_message=?,
		started_at=COALESCE(started_at, ?), finished_at=?,
		timestamp=CURRENT_TIMESTAMP WHERE uuid=?`
	_, err := r.db.ExecContext(ctx, q, status, logs, errMsg, startedAt, finishedAt, uuid)
	return err
}

func (r *CertJobRepository) queryJobs(ctx context.Context, q string, args ...interface{}) ([]*domain.CertJob, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*domain.CertJob
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func scanJob(s scanner) (*domain.CertJob, error) {
	var j domain.CertJob
	var startedAt, finishedAt sql.NullString
	err := s.Scan(
		&j.UUID, &j.CertUUID, &j.JobType, &j.Status,
		&j.Logs, &j.ErrorMsg,
		&startedAt, &finishedAt, &j.Created, &j.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("scan job: %w", err)
	}
	if startedAt.Valid && startedAt.String != "" {
		if t, ok := parseSQLiteTime(startedAt.String); ok {
			j.StartedAt = &t
		}
	}
	if finishedAt.Valid && finishedAt.String != "" {
		if t, ok := parseSQLiteTime(finishedAt.String); ok {
			j.FinishedAt = &t
		}
	}
	return &j, nil
}

// ─── CertDeploymentRepository ─────────────────────────────────────────────────

type CertDeploymentRepository struct{ db *sql.DB }

func NewCertDeploymentRepository(db *sql.DB) *CertDeploymentRepository {
	return &CertDeploymentRepository{db: db}
}

func (r *CertDeploymentRepository) FindByUUID(ctx context.Context, uuid string) (*domain.CertDeployment, error) {
	q := `SELECT d.uuid, d.cert_uuid, d.id_nodes, n.name,
		d.status, d.error_message, d.deployed_at, d.created, d.timestamp
		FROM certificate_deployments d
		LEFT JOIN nodes n ON n.id_nodes = d.id_nodes
		WHERE d.uuid=? LIMIT 1`
	row := r.db.QueryRowContext(ctx, q, uuid)
	d, err := scanCertDeployment(row)
	if err != nil {
		return nil, fmt.Errorf("deployment tidak ditemukan")
	}
	return d, nil
}

func (r *CertDeploymentRepository) ListByCert(ctx context.Context, certUUID string) ([]*domain.CertDeployment, error) {
	q := `SELECT d.uuid, d.cert_uuid, d.id_nodes, n.name,
		d.status, d.error_message, d.deployed_at, d.created, d.timestamp
		FROM certificate_deployments d
		LEFT JOIN nodes n ON n.id_nodes = d.id_nodes
		WHERE d.cert_uuid=? ORDER BY d.created DESC`
	rows, err := r.db.QueryContext(ctx, q, certUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deployments []*domain.CertDeployment
	for rows.Next() {
		d, err := scanCertDeployment(rows)
		if err != nil {
			return nil, err
		}
		deployments = append(deployments, d)
	}
	return deployments, rows.Err()
}

func (r *CertDeploymentRepository) Create(ctx context.Context, d *domain.CertDeployment) error {
	q := `INSERT INTO certificate_deployments
		(uuid, cert_uuid, id_nodes, status, error_message)
		VALUES (?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, q, d.UUID, d.CertUUID, d.NodeID, d.Status, d.ErrorMsg)
	return err
}

func (r *CertDeploymentRepository) UpdateStatus(ctx context.Context, uuid, status, errMsg string) error {
	var deployedAt interface{}
	if status == string(domain.DeployStatusSuccess) {
		deployedAt = time.Now().UTC().Format(time.RFC3339)
	}
	q := `UPDATE certificate_deployments SET status=?, error_message=?,
		deployed_at=?, timestamp=CURRENT_TIMESTAMP WHERE uuid=?`
	_, err := r.db.ExecContext(ctx, q, status, errMsg, deployedAt, uuid)
	return err
}

// timeToSQL mengkonversi *time.Time ke string RFC3339 UTC untuk penyimpanan konsisten di SQLite.
// Menghindari time.Time.String() yang menghasilkan format non-standar dengan timezone lokal dan m=+...
func timeToSQL(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// parseSQLiteTime mencoba beberapa format datetime yang mungkin disimpan SQLite.
// Menangani berbagai format hasil time.Time.String() dari driver lama.
func parseSQLiteTime(s string) (time.Time, bool) {
	// Strip monotonic clock reading (m=+...) dari Go's time.Time.String()
	if idx := len(s) - 1; idx > 0 {
		if i := strings.LastIndex(s, " m="); i > 0 {
			s = s[:i]
		}
	}
	s = strings.TrimSpace(s)

	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST", // time.Time.String() dengan nanodetik
		"2006-01-02 15:04:05 -0700 MST",            // time.Time.String() tanpa nanodetik
		"2006-01-02 15:04:05",                       // SQLite CURRENT_TIMESTAMP
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func scanCertDeployment(s scanner) (*domain.CertDeployment, error) {
	var d domain.CertDeployment
	var nodeName sql.NullString
	var deployedAt sql.NullString
	err := s.Scan(
		&d.UUID, &d.CertUUID, &d.NodeID, &nodeName,
		&d.Status, &d.ErrorMsg, &deployedAt, &d.Created, &d.Timestamp,
	)
	if err == sql.ErrNoRows {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("scan deployment: %w", err)
	}
	d.NodeName = nodeName.String
	if deployedAt.Valid && deployedAt.String != "" {
		if t, ok := parseSQLiteTime(deployedAt.String); ok {
			d.DeployedAt = &t
		}
	}
	return &d, nil
}

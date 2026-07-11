package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/aefw/hapm/internal/domain"
)

// haproxyNameRe memvalidasi nama yang aman dipakai dalam konfigurasi HAProxy.
// HAProxy hanya mengizinkan: huruf, angka, underscore, hyphen, dan dot.
// Spasi, @, !, dan karakter lain akan menyebabkan config error.
var haproxyNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$`)

func isValidHAProxyName(name string) bool {
	return haproxyNameRe.MatchString(name)
}

// backendService implements domain.BackendService
type backendService struct {
	repo     domain.BackendRepository
	auditSvc domain.AuditService
}

// NewBackendService membuat instance BackendService baru
func NewBackendService(repo domain.BackendRepository, auditSvc domain.AuditService) domain.BackendService {
	return &backendService{repo: repo, auditSvc: auditSvc}
}

// GetPoolByID mengambil backend pool berdasarkan ID (beserta servers)
func (s *backendService) GetPoolByID(ctx context.Context, id int) (*domain.BackendPool, error) {
	pool, err := s.repo.FindPoolByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("backend: find pool by id: %w", err)
	}
	return pool, nil
}

// ListPools mengembalikan semua backend pool beserta servers dengan filter dan pagination
func (s *backendService) ListPools(ctx context.Context, filter domain.ListFilter) ([]*domain.BackendPool, int, error) {
	pools, total, err := s.repo.ListPools(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("backend: list pools: %w", err)
	}
	return pools, total, nil
}

// CreatePool membuat backend pool baru
func (s *backendService) CreatePool(ctx context.Context, req *domain.CreatePoolRequest, actorID int) (*domain.BackendPool, error) {
	if req.Name == "" {
		return nil, errors.New("pool name is required")
	}
	if !isValidHAProxyName(req.Name) {
		return nil, errors.New("pool name tidak valid: hanya boleh huruf, angka, underscore (_), hyphen (-), dan dot (.)")
	}
	if !isValidAlgorithm(req.Algorithm) {
		return nil, errors.New("invalid algorithm, must be one of: roundrobin, leastconn, source")
	}

	// Cek duplikat nama
	if _, err := s.repo.FindPoolByName(ctx, req.Name); err == nil {
		return nil, errors.New("pool name already exists")
	}

	// Set default timeout jika tidak diisi
	timeoutConnect := req.TimeoutConnect
	if timeoutConnect <= 0 {
		timeoutConnect = 5000
	}
	timeoutServer := req.TimeoutServer
	if timeoutServer <= 0 {
		timeoutServer = 30000
	}

	hcConf, err := resolveHealthCheck(req)
	if err != nil {
		return nil, err
	}

	protocol, sslMode, fwdHeaders, err := resolveBackendProtocol(req, nil)
	if err != nil {
		return nil, err
	}

	pool := &domain.BackendPool{
		Name:            req.Name,
		Description:     req.Description,
		Algorithm:       req.Algorithm,
		TimeoutConnect:  timeoutConnect,
		TimeoutServer:   timeoutServer,
		Protocol:        protocol,
		SSLMode:         sslMode,
		ForwardHeaders:  fwdHeaders,
		HealthCheckConf: hcConf,
		HealthCheck:     hcConf.IsEnabled(),
	}

	var id int
	if req.Servers != nil && len(*req.Servers) > 0 {
		// Validasi semua server terlebih dahulu sebelum menyimpan apapun
		servers, err := validateAndBuildServers(*req.Servers)
		if err != nil {
			return nil, err
		}
		id, err = s.repo.CreatePoolWithServers(ctx, pool, servers)
		if err != nil {
			return nil, fmt.Errorf("backend: create pool with servers: %w", err)
		}
	} else {
		id, err = s.repo.CreatePool(ctx, pool)
		if err != nil {
			return nil, fmt.Errorf("backend: create pool: %w", err)
		}
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionBackendCreated,
		ResourceType: "backend_pool",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Created backend pool %s (health_check: %s)", req.Name, hcConf.Type),
	})

	created, err := s.repo.FindPoolByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("backend: fetch pool after create: %w", err)
	}
	return created, nil
}

// UpdatePool memperbarui backend pool
func (s *backendService) UpdatePool(ctx context.Context, id int, req *domain.CreatePoolRequest, actorID int) (*domain.BackendPool, error) {
	pool, err := s.repo.FindPoolByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("backend: find pool by id: %w", err)
	}

	if req.Name != "" && req.Name != pool.Name {
		if !isValidHAProxyName(req.Name) {
			return nil, errors.New("pool name tidak valid: hanya boleh huruf, angka, underscore (_), hyphen (-), dan dot (.)")
		}
		if _, err := s.repo.FindPoolByName(ctx, req.Name); err == nil {
			return nil, errors.New("pool name already exists")
		}
		pool.Name = req.Name
	}
	if req.Description != "" {
		pool.Description = req.Description
	}
	if req.Algorithm != "" {
		if !isValidAlgorithm(req.Algorithm) {
			return nil, errors.New("invalid algorithm")
		}
		pool.Algorithm = req.Algorithm
	}
	if req.TimeoutConnect > 0 {
		pool.TimeoutConnect = req.TimeoutConnect
	}
	if req.TimeoutServer > 0 {
		pool.TimeoutServer = req.TimeoutServer
	}

	hcConf, err := resolveHealthCheck(req)
	if err != nil {
		return nil, err
	}

	// Catat perubahan health check jika berbeda
	hcChanged := pool.HealthCheckConf.Type != hcConf.Type
	pool.HealthCheckConf = hcConf
	pool.HealthCheck = hcConf.IsEnabled()

	protocol, sslMode, fwdHeaders, err := resolveBackendProtocol(req, pool)
	if err != nil {
		return nil, err
	}
	pool.Protocol = protocol
	pool.SSLMode = sslMode
	pool.ForwardHeaders = fwdHeaders

	// Jika servers disertakan, validasi dulu sebelum menyentuh DB
	var replaceServers []*domain.BackendServer
	if req.Servers != nil {
		replaceServers, err = validateAndBuildServers(*req.Servers)
		if err != nil {
			return nil, err
		}
	}

	if err := s.repo.UpdatePool(ctx, pool); err != nil {
		return nil, fmt.Errorf("backend: update pool: %w", err)
	}

	// Ganti semua server secara atomik jika field servers diisi di request
	if req.Servers != nil {
		if err := s.repo.ReplaceServers(ctx, id, replaceServers); err != nil {
			return nil, fmt.Errorf("backend: replace servers: %w", err)
		}
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionBackendUpdated,
		ResourceType: "backend_pool",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Updated backend pool %s", pool.Name),
	})

	if hcChanged {
		_ = s.auditSvc.Log(ctx, &domain.AuditLog{
			UserID:       &actorID,
			Action:       domain.AuditActionBackendHealthCheckChanged,
			ResourceType: "backend_pool",
			ResourceID:   &id,
			Detail:       fmt.Sprintf("Health check diubah menjadi %s pada pool %s", hcConf.Type, pool.Name),
		})
	}

	updated, err := s.repo.FindPoolByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("backend: fetch pool after update: %w", err)
	}
	return updated, nil
}

// DeletePool menghapus backend pool
func (s *backendService) DeletePool(ctx context.Context, id int, actorID int) error {
	pool, err := s.repo.FindPoolByID(ctx, id)
	if err != nil {
		return fmt.Errorf("backend: find pool by id: %w", err)
	}

	if err := s.repo.DeletePool(ctx, id); err != nil {
		return fmt.Errorf("backend: delete pool: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionBackendDeleted,
		ResourceType: "backend_pool",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Deleted backend pool %s", pool.Name),
	})

	return nil
}

// validateAndBuildServers memvalidasi semua server request dan mengonversinya ke domain.BackendServer.
// Seluruh validasi dijalankan sebelum pool disimpan, sehingga error server tidak menyisakan pool kosong.
func validateAndBuildServers(reqs []domain.CreateServerRequest) ([]*domain.BackendServer, error) {
	servers := make([]*domain.BackendServer, 0, len(reqs))
	for i, r := range reqs {
		if r.Name == "" {
			return nil, fmt.Errorf("server[%d]: name wajib diisi", i)
		}
		if !isValidHAProxyName(r.Name) {
			return nil, fmt.Errorf("server[%d] %q: name tidak valid (hanya huruf, angka, underscore, hyphen, dot)", i, r.Name)
		}
		if r.IPAddress == "" {
			return nil, fmt.Errorf("server[%d] %q: ip_address wajib diisi", i, r.Name)
		}
		if r.Port <= 0 || r.Port > 65535 {
			return nil, fmt.Errorf("server[%d] %q: port tidak valid (%d)", i, r.Name, r.Port)
		}
		weight := r.Weight
		if weight <= 0 {
			weight = 1
		}
		servers = append(servers, &domain.BackendServer{
			Name:      r.Name,
			IPAddress: r.IPAddress,
			Port:      r.Port,
			Weight:    weight,
			Backup:    r.Backup,
			Enabled:   r.Enabled,
		})
	}
	return servers, nil
}

// isValidAlgorithm memvalidasi algoritma load balancing
func isValidAlgorithm(a domain.Algorithm) bool {
	switch a {
	case domain.AlgorithmRoundRobin, domain.AlgorithmLeastConn, domain.AlgorithmSource:
		return true
	}
	return false
}

// resolveHealthCheck menentukan HealthCheckConfig dari CreatePoolRequest.
// Prioritas: HealthCheckType (string) → HealthCheck (bool, backward compat) → none.
func resolveHealthCheck(req *domain.CreatePoolRequest) (domain.HealthCheckConfig, error) {
	hcType := domain.HealthCheckType(req.HealthCheckType)

	// Backward compat: jika health_check_type tidak diisi tapi health_check=true → default HTTP
	if hcType == "" {
		if req.HealthCheck {
			hcType = domain.HealthCheckHTTP
		} else {
			return domain.HealthCheckConfig{Type: domain.HealthCheckNone}, nil
		}
	}

	cfg := domain.HealthCheckConfig{Type: hcType}
	if req.HealthCheckConfig != nil {
		cfg.Path = req.HealthCheckConfig.Path
		cfg.Expect = req.HealthCheckConfig.Expect
		cfg.User = req.HealthCheckConfig.User
		cfg.Custom = req.HealthCheckConfig.Custom
	}

	if err := validateHealthCheck(cfg); err != nil {
		return domain.HealthCheckConfig{}, err
	}
	return cfg, nil
}

// validateHealthCheck memvalidasi konsistensi konfigurasi health check
func validateHealthCheck(cfg domain.HealthCheckConfig) error {
	switch cfg.Type {
	case domain.HealthCheckNone, "":
		return nil
	case domain.HealthCheckTCP, domain.HealthCheckHTTP, domain.HealthCheckHTTPS,
		domain.HealthCheckSSH, domain.HealthCheckRedis:
		return nil
	case domain.HealthCheckMySQL:
		if cfg.User == "" {
			return fmt.Errorf("health check MYSQL membutuhkan health_check_config.user (contoh: \"haproxy\")")
		}
		return nil
	case domain.HealthCheckPostgreSQL:
		if cfg.User == "" {
			return fmt.Errorf("health check POSTGRESQL membutuhkan health_check_config.user (contoh: \"haproxy\")")
		}
		return nil
	case domain.HealthCheckCustom:
		if cfg.Custom == "" {
			return fmt.Errorf("health check CUSTOM membutuhkan health_check_config.custom berisi HAProxy directives")
		}
		return nil
	default:
		return fmt.Errorf("health_check_type tidak valid: %s (gunakan: none, TCP, HTTP, HTTPS, SSH, MYSQL, POSTGRESQL, REDIS, CUSTOM)", cfg.Type)
	}
}

// resolveBackendProtocol menentukan Protocol, SSLMode, dan ForwardHeaders dari request.
// existing diisi saat update (nilai lama dipakai jika field kosong/nil), nil saat create.
func resolveBackendProtocol(req *domain.CreatePoolRequest, existing *domain.BackendPool) (domain.BackendProtocol, domain.BackendSSLMode, bool, error) {
	protocol := req.Protocol
	sslMode := req.SSLMode

	// Default untuk create: ambil dari existing (update) atau default http/none (create)
	if protocol == "" {
		if existing != nil {
			protocol = existing.Protocol
		} else {
			protocol = domain.BackendProtocolHTTP
		}
	}
	if sslMode == "" {
		if existing != nil {
			sslMode = existing.SSLMode
		} else {
			sslMode = domain.BackendSSLModeNone
		}
	}

	// ForwardHeaders: *bool nil → keep existing (update) atau default true (create)
	fwdHeaders := true
	if req.ForwardHeaders != nil {
		fwdHeaders = *req.ForwardHeaders
	} else if existing != nil {
		fwdHeaders = existing.ForwardHeaders
	}

	// Validasi kombinasi protocol + ssl_mode
	switch protocol {
	case domain.BackendProtocolHTTPS:
		if sslMode == domain.BackendSSLModeNone || sslMode == "" {
			return "", "", false, errors.New("protocol https membutuhkan ssl_mode: gunakan 'trusted' atau 'self_signed'")
		}
		if sslMode != domain.BackendSSLModeTrusted && sslMode != domain.BackendSSLModeSelfSigned {
			return "", "", false, fmt.Errorf("ssl_mode tidak valid: %s (gunakan: trusted, self_signed)", sslMode)
		}
	case domain.BackendProtocolHTTP, domain.BackendProtocolTCP:
		if sslMode != domain.BackendSSLModeNone && sslMode != "" {
			return "", "", false, fmt.Errorf("ssl_mode hanya berlaku untuk protocol https, bukan %s", protocol)
		}
		sslMode = domain.BackendSSLModeNone
	default:
		return "", "", false, fmt.Errorf("protocol tidak valid: %s (gunakan: http, https, tcp)", protocol)
	}

	return protocol, sslMode, fwdHeaders, nil
}

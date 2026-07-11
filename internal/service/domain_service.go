package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/aefw/hapm/internal/domain"
)

// domainNameRe memvalidasi nama domain yang aman dipakai dalam konfigurasi HAProxy.
// Mendukung: domain biasa (example.com), subdomain (api.example.com),
// wildcard (*.example.com), internal hostname (localhost), dan IP address.
// Tidak mengizinkan spasi, @, !, dan karakter lain yang merusak ACL HAProxy.
var domainNameRe = regexp.MustCompile(
	`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`,
)

func isValidDomainName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	return domainNameRe.MatchString(name)
}

// domainService implements domain.DomainService
type domainService struct {
	repo        domain.DomainRepository
	backendRepo domain.BackendRepository
	auditSvc    domain.AuditService
}

// NewDomainService membuat instance DomainService baru
func NewDomainService(
	repo domain.DomainRepository,
	backendRepo domain.BackendRepository,
	auditSvc domain.AuditService,
) domain.DomainService {
	return &domainService{repo: repo, backendRepo: backendRepo, auditSvc: auditSvc}
}

// GetByID mengambil domain entry berdasarkan ID
func (s *domainService) GetByID(ctx context.Context, id int) (*domain.DomainEntry, error) {
	d, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("domain: find by id: %w", err)
	}
	return d, nil
}

// List mengembalikan semua domain entries dengan filter dan pagination
func (s *domainService) List(ctx context.Context, filter domain.ListFilter) ([]*domain.DomainEntry, int, error) {
	domains, total, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("domain: list: %w", err)
	}
	return domains, total, nil
}

// Create membuat domain entry baru
func (s *domainService) Create(ctx context.Context, req *domain.CreateDomainRequest, actorID int) (*domain.DomainEntry, error) {
	if req.DomainName == "" {
		return nil, errors.New("domain name is required")
	}
	if !isValidDomainName(req.DomainName) {
		return nil, errors.New("domain name tidak valid: hanya boleh huruf, angka, hyphen (-), dot (.), dan wildcard (*.) di awal")
	}
	if req.BackendPoolID <= 0 {
		return nil, errors.New("backend pool id is required")
	}

	// Validasi SSL mode
	if !isValidSSLMode(req.SSLMode) {
		return nil, errors.New("invalid ssl_mode, must be: none, terminate, passthrough")
	}

	// Jika SSL mode terminate, cert_uuid wajib
	if req.SSLMode == domain.SSLModeTerminate && req.CertUUID == nil {
		return nil, errors.New("cert_uuid is required when ssl_mode is terminate")
	}

	// Validasi backend pool ada
	if _, err := s.backendRepo.FindPoolByID(ctx, req.BackendPoolID); err != nil {
		return nil, errors.New("backend pool not found")
	}

	// Cek duplikat domain name
	if _, err := s.repo.FindByDomainName(ctx, req.DomainName); err == nil {
		return nil, errors.New("domain already exists")
	}

	entry := &domain.DomainEntry{
		DomainName:    req.DomainName,
		BackendPoolID: req.BackendPoolID,
		SSLMode:       req.SSLMode,
		CertUUID:      req.CertUUID,
		AuthGroupID:   req.AuthGroupID,
		HTTPRedirect:  req.HTTPRedirect,
		Enabled:       req.Enabled,
		Description:   req.Description,
	}

	id, err := s.repo.Create(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("domain: create: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionDomainCreated,
		ResourceType: "domain",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Created domain %s -> pool %d", req.DomainName, req.BackendPoolID),
	})

	created, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("domain: fetch after create: %w", err)
	}
	return created, nil
}

// Update memperbarui domain entry
func (s *domainService) Update(ctx context.Context, id int, req *domain.CreateDomainRequest, actorID int) (*domain.DomainEntry, error) {
	entry, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("domain: find by id: %w", err)
	}

	if req.DomainName != "" && req.DomainName != entry.DomainName {
		if !isValidDomainName(req.DomainName) {
			return nil, errors.New("domain name tidak valid: hanya boleh huruf, angka, hyphen (-), dot (.), dan wildcard (*.) di awal")
		}
		if _, err := s.repo.FindByDomainName(ctx, req.DomainName); err == nil {
			return nil, errors.New("domain already exists")
		}
		entry.DomainName = req.DomainName
	}

	if req.BackendPoolID > 0 {
		if _, err := s.backendRepo.FindPoolByID(ctx, req.BackendPoolID); err != nil {
			return nil, errors.New("backend pool not found")
		}
		entry.BackendPoolID = req.BackendPoolID
	}

	if req.SSLMode != "" {
		if !isValidSSLMode(req.SSLMode) {
			return nil, errors.New("invalid ssl_mode")
		}
		entry.SSLMode = req.SSLMode
	}

	if req.CertUUID != nil {
		entry.CertUUID = req.CertUUID
	}

	// AuthGroupID: nil pointer = tidak ubah, pointer ke 0 = hapus auth, pointer ke N = set group N
	entry.AuthGroupID = req.AuthGroupID

	entry.HTTPRedirect = req.HTTPRedirect
	entry.Enabled = req.Enabled
	if req.Description != "" {
		entry.Description = req.Description
	}

	if err := s.repo.Update(ctx, entry); err != nil {
		return nil, fmt.Errorf("domain: update: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionDomainUpdated,
		ResourceType: "domain",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Updated domain %s", entry.DomainName),
	})

	return entry, nil
}

// Delete menghapus domain entry
func (s *domainService) Delete(ctx context.Context, id int, actorID int) error {
	entry, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("domain: find by id: %w", err)
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("domain: delete: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionDomainDeleted,
		ResourceType: "domain",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Deleted domain %s", entry.DomainName),
	})

	return nil
}

// isValidSSLMode memvalidasi nilai ssl mode
func isValidSSLMode(m domain.SSLMode) bool {
	switch m {
	case domain.SSLModeNone, domain.SSLModeTerminate, domain.SSLModePassthrough:
		return true
	case "": // kosong = tidak diubah
		return true
	}
	return false
}

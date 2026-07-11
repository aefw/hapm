package service

import (
	"context"
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/pkg/iputil"
)

// auditService implements domain.AuditService
type auditService struct {
	repo      domain.AuditRepository
	proxyMode iputil.Mode
}

// NewAuditService membuat instance AuditService baru
func NewAuditService(cfg *config.Config, repo domain.AuditRepository) domain.AuditService {
	return &auditService{
		repo:      repo,
		proxyMode: iputil.Mode(cfg.Proxy.Mode),
	}
}

// Log mencatat audit log ke database
func (s *auditService) Log(ctx context.Context, log *domain.AuditLog) error {
	return s.repo.Create(ctx, log)
}

// LogFromRequest adalah helper untuk membuat audit log dari request HTTP
func (s *auditService) LogFromRequest(
	ctx context.Context,
	r *http.Request,
	userID *int,
	action, resourceType string,
	resourceID *int,
	detail string,
) error {
	entry := &domain.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    iputil.RealIP(r, s.proxyMode),
		UserAgent:    r.UserAgent(),
		Detail:       detail,
	}
	return s.repo.Create(ctx, entry)
}

// List mengembalikan daftar audit log dengan filter dan total count
func (s *auditService) List(ctx context.Context, filter domain.AuditFilter) ([]*domain.AuditLog, int, error) {
	return s.repo.List(ctx, filter)
}

// GetByID mengambil audit log berdasarkan ID
func (s *auditService) GetByID(ctx context.Context, id int) (*domain.AuditLog, error) {
	return s.repo.FindByID(ctx, id)
}

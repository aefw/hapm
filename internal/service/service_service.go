package service

import (
	"context"
	"fmt"
	"regexp"

	"github.com/aefw/hapm/internal/domain"
)

// serviceService implements domain.ServiceService
type serviceService struct {
	repo        domain.ServiceRepository
	backendRepo domain.BackendRepository
	auditSvc    domain.AuditService
}

// NewServiceService membuat instance ServiceService baru
func NewServiceService(
	repo domain.ServiceRepository,
	backendRepo domain.BackendRepository,
	auditSvc domain.AuditService,
) domain.ServiceService {
	return &serviceService{
		repo:        repo,
		backendRepo: backendRepo,
		auditSvc:    auditSvc,
	}
}

var reServiceName = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

func (s *serviceService) GetByID(ctx context.Context, id int) (*domain.Service, error) {
	svc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("service: find by id: %w", err)
	}
	return svc, nil
}

func (s *serviceService) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Service, int, error) {
	list, total, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("service: list: %w", err)
	}
	return list, total, nil
}

func (s *serviceService) Create(ctx context.Context, req *domain.CreateServiceRequest, actorID int) (*domain.Service, error) {
	if err := s.validate(ctx, req, 0); err != nil {
		return nil, err
	}

	svc := &domain.Service{
		Name:          req.Name,
		ServiceType:   req.ServiceType,
		ListenPort:    req.ListenPort,
		BackendPoolID: req.BackendPoolID,
		Description:   req.Description,
		Enabled:       req.Enabled,
	}

	id, err := s.repo.Create(ctx, svc)
	if err != nil {
		return nil, fmt.Errorf("service: create: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionServiceCreated,
		ResourceType: "service",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Created service %s (port %d, type %s)", req.Name, req.ListenPort, req.ServiceType),
	})

	created, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("service: fetch after create: %w", err)
	}
	return created, nil
}

func (s *serviceService) Update(ctx context.Context, id int, req *domain.CreateServiceRequest, actorID int) (*domain.Service, error) {
	existing, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("service: find by id: %w", err)
	}

	if err := s.validate(ctx, req, id); err != nil {
		return nil, err
	}

	existing.Name = req.Name
	existing.ServiceType = req.ServiceType
	existing.ListenPort = req.ListenPort
	existing.BackendPoolID = req.BackendPoolID
	existing.Description = req.Description
	existing.Enabled = req.Enabled

	if err := s.repo.Update(ctx, existing); err != nil {
		return nil, fmt.Errorf("service: update: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionServiceUpdated,
		ResourceType: "service",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Updated service %s (port %d, type %s)", req.Name, req.ListenPort, req.ServiceType),
	})

	updated, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("service: fetch after update: %w", err)
	}
	return updated, nil
}

func (s *serviceService) Delete(ctx context.Context, id int, actorID int) error {
	svc, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("service: find by id: %w", err)
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("service: delete: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionServiceDeleted,
		ResourceType: "service",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Deleted service %s (port %d)", svc.Name, svc.ListenPort),
	})

	return nil
}

// validate memvalidasi CreateServiceRequest sebelum create/update
func (s *serviceService) validate(ctx context.Context, req *domain.CreateServiceRequest, skipID int) error {
	if req.Name == "" {
		return fmt.Errorf("service: name wajib diisi")
	}
	if !reServiceName.MatchString(req.Name) {
		return fmt.Errorf("service: name tidak valid: hanya boleh huruf, angka, underscore (_), dan hyphen (-)")
	}

	switch req.ServiceType {
	case domain.ServiceTypeHTTP, domain.ServiceTypeHTTPS, domain.ServiceTypeTCP:
	default:
		return fmt.Errorf("service: service_type tidak didukung: gunakan HTTP, HTTPS, atau TCP")
	}

	if req.ListenPort < 1 || req.ListenPort > 65535 {
		return fmt.Errorf("service: invalid port: listen_port harus antara 1-65535")
	}

	if req.BackendPoolID <= 0 {
		return fmt.Errorf("service: id_backend_pools wajib diisi")
	}

	if _, err := s.backendRepo.FindPoolByID(ctx, req.BackendPoolID); err != nil {
		return fmt.Errorf("service: backend pool tidak ditemukan")
	}

	// Cek duplikat nama (skip diri sendiri saat update)
	if existing, err := s.repo.FindByName(ctx, req.Name); err == nil && existing.ID != skipID {
		return fmt.Errorf("service: name sudah ada")
	}

	// Cek port conflict (skip diri sendiri saat update)
	if existing, err := s.repo.FindByPort(ctx, req.ListenPort); err == nil && existing.ID != skipID {
		return fmt.Errorf("service: listen_port %d sudah digunakan oleh service '%s'", req.ListenPort, existing.Name)
	}

	return nil
}

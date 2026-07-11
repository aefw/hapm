package service

import (
	"context"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
)

type certJobService struct {
	repo domain.CertJobRepository
}

func NewCertJobService(repo domain.CertJobRepository) domain.CertJobService {
	return &certJobService{repo: repo}
}

func (s *certJobService) GetByUUID(ctx context.Context, uuid string) (*domain.CertJob, error) {
	j, err := s.repo.FindByUUID(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("job tidak ditemukan")
	}
	return j, nil
}

func (s *certJobService) ListByCert(ctx context.Context, certUUID string, limit int) ([]*domain.CertJob, error) {
	return s.repo.ListByCert(ctx, certUUID, limit)
}

func (s *certJobService) ListAll(ctx context.Context, limit int) ([]*domain.CertJob, error) {
	return s.repo.ListAll(ctx, limit)
}

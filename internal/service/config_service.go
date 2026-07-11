package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/pkg/haproxy"
)

// configService implements domain.ConfigService
type configService struct {
	nodeRepo      domain.NodeRepository
	backendRepo   domain.BackendRepository
	domainRepo    domain.DomainRepository
	certRepo      domain.CertificateRepository
	serviceRepo   domain.ServiceRepository
	authGroupRepo domain.AuthGroupRepository
	generator     haproxy.Generator
}

// NewConfigService membuat instance ConfigService baru
func NewConfigService(
	nodeRepo domain.NodeRepository,
	backendRepo domain.BackendRepository,
	domainRepo domain.DomainRepository,
	certRepo domain.CertificateRepository,
	serviceRepo domain.ServiceRepository,
	authGroupRepo domain.AuthGroupRepository,
	generator haproxy.Generator,
) domain.ConfigService {
	return &configService{
		nodeRepo:      nodeRepo,
		backendRepo:   backendRepo,
		domainRepo:    domainRepo,
		certRepo:      certRepo,
		serviceRepo:   serviceRepo,
		authGroupRepo: authGroupRepo,
		generator:     generator,
	}
}

// GenerateForNode menghasilkan konfigurasi HAProxy lengkap untuk satu node
func (s *configService) GenerateForNode(ctx context.Context, nodeID int) (*domain.GeneratedConfig, error) {
	node, err := s.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("config: node not found: %w", err)
	}

	domains, err := s.domainRepo.ListEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("config: list enabled domains: %w", err)
	}

	pools, _, err := s.backendRepo.ListPools(ctx, domain.ListFilter{})
	if err != nil {
		return nil, fmt.Errorf("config: list pools: %w", err)
	}

	// Ambil certificate CMC yang digunakan oleh domain-domain ini
	certUUIDs := collectCertUUIDs(domains)
	certs := make([]*domain.Certificate, 0, len(certUUIDs))
	for _, cu := range certUUIDs {
		cert, err := s.certRepo.FindByUUID(ctx, cu)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	services, err := s.serviceRepo.ListEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("config: list enabled services: %w", err)
	}

	authGroups, err := s.authGroupRepo.ListEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("config: list enabled auth groups: %w", err)
	}

	content, hostsMap, err := s.generator.Generate(ctx, node, domains, pools, certs, services, authGroups)
	if err != nil {
		return nil, fmt.Errorf("config: generate: %w", err)
	}

	h := sha256.Sum256([]byte(content))
	hash := hex.EncodeToString(h[:])

	return &domain.GeneratedConfig{
		NodeID:   nodeID,
		Content:  content,
		HostsMap: hostsMap,
		Hash:     hash,
	}, nil
}

// ValidateConfig menghasilkan dan memvalidasi konfigurasi untuk node tertentu
func (s *configService) ValidateConfig(ctx context.Context, nodeID int) (bool, string, error) {
	generated, err := s.GenerateForNode(ctx, nodeID)
	if err != nil {
		return false, "", fmt.Errorf("config: generate for validation: %w", err)
	}
	if generated.Content == "" {
		return false, "generated config is empty", nil
	}
	return true, "", nil
}

// collectCertUUIDs mengumpulkan unique cert UUIDs dari daftar domain
func collectCertUUIDs(domains []*domain.DomainEntry) []string {
	seen := make(map[string]bool)
	var uuids []string
	for _, d := range domains {
		if d.CertUUID != nil && !seen[*d.CertUUID] {
			seen[*d.CertUUID] = true
			uuids = append(uuids, *d.CertUUID)
		}
	}
	return uuids
}

package service

import (
	"context"
	"sync"
	"time"

	"github.com/aefw/hapm/internal/domain"
)

type dashboardService struct {
	nodeRepo    domain.NodeRepository
	domainRepo  domain.DomainRepository
	backendRepo domain.BackendRepository
	serviceRepo domain.ServiceRepository
	certRepo    domain.CertificateRepository
	deployRepo  domain.DeploymentRepository
	auditRepo   domain.AuditRepository
	monSvc      domain.MonitoringService
}

func NewDashboardService(
	nodeRepo domain.NodeRepository,
	domainRepo domain.DomainRepository,
	backendRepo domain.BackendRepository,
	serviceRepo domain.ServiceRepository,
	certRepo domain.CertificateRepository,
	deployRepo domain.DeploymentRepository,
	auditRepo domain.AuditRepository,
	monSvc domain.MonitoringService,
) domain.DashboardService {
	return &dashboardService{
		nodeRepo:    nodeRepo,
		domainRepo:  domainRepo,
		backendRepo: backendRepo,
		serviceRepo: serviceRepo,
		certRepo:    certRepo,
		deployRepo:  deployRepo,
		auditRepo:   auditRepo,
		monSvc:      monSvc,
	}
}

// GetOverview mengambil ringkasan seluruh sistem dari DB tanpa SSH — response cepat.
func (s *dashboardService) GetOverview(ctx context.Context) (*domain.DashboardData, error) {
	// Ambil semua data dari DB secara paralel
	type result struct {
		nodes       []*domain.Node
		domains     []*domain.DomainEntry
		backends    []*domain.BackendPool
		services    []*domain.Service
		certs       []*domain.Certificate
		deployments []*domain.Deployment
		auditLogs   []*domain.AuditLog
		errs        []error
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		res result
	)

	collect := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				mu.Lock()
				res.errs = append(res.errs, err)
				mu.Unlock()
			}
		}()
	}

	collect(func() error {
		n, _, err := s.nodeRepo.List(ctx, domain.ListFilter{})
		mu.Lock(); res.nodes = n; mu.Unlock()
		return err
	})
	collect(func() error {
		d, _, err := s.domainRepo.List(ctx, domain.ListFilter{})
		mu.Lock(); res.domains = d; mu.Unlock()
		return err
	})
	collect(func() error {
		b, _, err := s.backendRepo.ListPools(ctx, domain.ListFilter{})
		mu.Lock(); res.backends = b; mu.Unlock()
		return err
	})
	collect(func() error {
		sv, _, err := s.serviceRepo.List(ctx, domain.ListFilter{})
		mu.Lock(); res.services = sv; mu.Unlock()
		return err
	})
	collect(func() error {
		c, _, err := s.certRepo.List(ctx, domain.ListFilter{})
		mu.Lock(); res.certs = c; mu.Unlock()
		return err
	})
	collect(func() error {
		d, err := s.deployRepo.ListRecent(ctx, 10)
		mu.Lock(); res.deployments = d; mu.Unlock()
		return err
	})
	collect(func() error {
		logs, _, err := s.auditRepo.List(ctx, domain.AuditFilter{Limit: 10})
		mu.Lock(); res.auditLogs = logs; mu.Unlock()
		return err
	})

	wg.Wait()

	// Bangun node summary dengan last deployment per node
	lastDeploy := buildLastDeployMap(res.deployments)

	nodeSummaries := make([]*domain.DashboardNodeSummary, 0, len(res.nodes))
	nodeCounts := domain.DashboardNodeCount{Total: len(res.nodes)}
	for _, n := range res.nodes {
		switch n.Status {
		case domain.NodeStatusOnline:
			nodeCounts.Online++
		case domain.NodeStatusOffline:
			nodeCounts.Offline++
		default:
			nodeCounts.Unknown++
		}
		ns := &domain.DashboardNodeSummary{
			ID:             n.ID,
			Name:           n.Name,
			IPAddress:      n.IPAddress,
			Status:         n.Status,
			HAProxyVersion: n.HAProxyVersion,
			LastChecked:    n.LastChecked,
			LastDeployment: lastDeploy[n.ID],
		}
		nodeSummaries = append(nodeSummaries, ns)
	}

	return &domain.DashboardData{
		Summary: domain.DashboardSummary{
			Nodes:    nodeCounts,
			Domains:  len(res.domains),
			Backends: len(res.backends),
			Services: len(res.services),
			SSLCerts: len(res.certs),
		},
		Nodes:             nodeSummaries,
		RecentDeployments: res.deployments,
		RecentAudit:       res.auditLogs,
	}, nil
}

// GetAllNodeStats mengambil live stats HAProxy dari semua node secara paralel.
// Setiap node diquery via SSH dengan timeout 15 detik. Node yang tidak bisa dihubungi
// tetap muncul di response dengan field error diisi.
func (s *dashboardService) GetAllNodeStats(ctx context.Context) ([]*domain.DashboardNodeStats, error) {
	nodes, _, err := s.nodeRepo.List(ctx, domain.ListFilter{})
	if err != nil {
		return nil, err
	}

	results := make([]*domain.DashboardNodeStats, len(nodes))
	var wg sync.WaitGroup

	for i, node := range nodes {
		wg.Add(1)
		go func(idx int, n *domain.Node) {
			defer wg.Done()

			entry := &domain.DashboardNodeStats{
				NodeID:    n.ID,
				NodeName:  n.Name,
				IPAddress: n.IPAddress,
				Status:    n.Status,
			}

			// Timeout per node: 15 detik agar tidak block terlalu lama
			tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			stats, err := s.monSvc.GetNodeStats(tctx, n.ID)
			if err != nil {
				entry.Error = err.Error()
			} else {
				entry.Stats = stats
			}

			results[idx] = entry
		}(i, node)
	}

	wg.Wait()
	return results, nil
}

// buildLastDeployMap membangun map nodeID → DashboardDeployInfo dari daftar deployment terbaru.
// Deployment sudah diurutkan DESC, jadi deployment pertama per node adalah yang terbaru.
func buildLastDeployMap(deployments []*domain.Deployment) map[int]*domain.DashboardDeployInfo {
	m := make(map[int]*domain.DashboardDeployInfo)
	for _, d := range deployments {
		if _, exists := m[d.NodeID]; !exists {
			m[d.NodeID] = &domain.DashboardDeployInfo{
				ID:         d.ID,
				Status:     d.Status,
				Stage:      d.Stage,
				FinishedAt: d.FinishedAt,
				Username:   d.Username,
			}
		}
	}
	return m
}

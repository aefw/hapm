package service

import (
	"context"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/pkg/haproxy"
	"github.com/aefw/hapm/pkg/ssh"
)

// monitoringService implements domain.MonitoringService
type monitoringService struct {
	nodeRepo       domain.NodeRepository
	statsCollector haproxy.StatsCollector
	sshClient      ssh.Client
}

// NewMonitoringService membuat instance MonitoringService baru
func NewMonitoringService(
	nodeRepo domain.NodeRepository,
	statsCollector haproxy.StatsCollector,
	sshClient ssh.Client,
) domain.MonitoringService {
	return &monitoringService{
		nodeRepo:       nodeRepo,
		statsCollector: statsCollector,
		sshClient:      sshClient,
	}
}

// GetNodeStats mengambil statistik lengkap HAProxy untuk satu node
func (s *monitoringService) GetNodeStats(ctx context.Context, nodeID int) (*domain.NodeStats, error) {
	node, err := s.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("monitoring: find node: %w", err)
	}

	conn, err := s.buildConn(node)
	if err != nil {
		return nil, err
	}

	stats, err := s.statsCollector.GetStats(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("monitoring: get stats: %w", err)
	}

	// Isi NodeID dan NodeName
	stats.NodeID = nodeID
	stats.NodeName = node.Name

	return stats, nil
}

// GetFrontendStats mengambil statistik frontend HAProxy untuk satu node
func (s *monitoringService) GetFrontendStats(ctx context.Context, nodeID int) ([]*domain.FrontendStats, error) {
	node, err := s.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("monitoring: find node: %w", err)
	}

	conn, err := s.buildConn(node)
	if err != nil {
		return nil, err
	}

	frontends, err := s.statsCollector.GetFrontendStats(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("monitoring: get frontend stats: %w", err)
	}

	return frontends, nil
}

// GetBackendStats mengambil statistik backend HAProxy untuk satu node
func (s *monitoringService) GetBackendStats(ctx context.Context, nodeID int) ([]*domain.BackendStats, error) {
	node, err := s.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("monitoring: find node: %w", err)
	}

	conn, err := s.buildConn(node)
	if err != nil {
		return nil, err
	}

	backends, err := s.statsCollector.GetBackendStats(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("monitoring: get backend stats: %w", err)
	}

	return backends, nil
}

// buildConn membangun ssh.Connection dari node entity.
// Catatan: monitoring_service tidak mendekripsi SSH key sendiri karena tidak
// memiliki akses ke config. Untuk produksi, inject cfg atau gunakan SSHKeyDecrypted.
// Untuk saat ini kita gunakan node.SSHPrivateKey langsung (sudah dienkripsi).
// NodeService bertanggung jawab atas dekripsi — monitoring hanya membaca stats.
func (s *monitoringService) buildConn(node *domain.Node) (*ssh.Connection, error) {
	if node.SSHPrivateKey == "" {
		return nil, fmt.Errorf("monitoring: node %d has no SSH key configured", node.ID)
	}

	return &ssh.Connection{
		Host:       node.IPAddress,
		Port:       node.SSHPort,
		User:       node.SSHUser,
		PrivateKey: node.SSHPrivateKey, // encrypted — caller harus dekripsi sebelum sampling
	}, nil
}

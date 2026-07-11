package service

import (
	"context"
	"fmt"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/domain"
	pkgssh "github.com/aefw/hapm/pkg/ssh"
	"github.com/aefw/hapm/pkg/storage"
	"github.com/aefw/hapm/internal/security"
	"github.com/google/uuid"
)

// distributionService implements domain.DistributionService
type distributionService struct {
	cfg        *config.Config
	certRepo   domain.CertificateRepository
	deployRepo domain.CertDeploymentRepository
	nodeRepo   domain.NodeRepository
	certStore  *storage.CertStore
	ssh        pkgssh.Client
	auditSvc   domain.AuditService
}

func NewDistributionService(
	cfg *config.Config,
	certRepo domain.CertificateRepository,
	deployRepo domain.CertDeploymentRepository,
	nodeRepo domain.NodeRepository,
	certStore *storage.CertStore,
	sshClient pkgssh.Client,
	auditSvc domain.AuditService,
) domain.DistributionService {
	return &distributionService{
		cfg: cfg, certRepo: certRepo, deployRepo: deployRepo,
		nodeRepo: nodeRepo, certStore: certStore, ssh: sshClient, auditSvc: auditSvc,
	}
}

func (s *distributionService) Distribute(ctx context.Context, certUUID string, nodeIDs []int, actorID int) ([]*domain.CertDeployment, error) {
	cert, err := s.certRepo.FindByUUID(ctx, certUUID)
	if err != nil {
		return nil, err
	}
	if cert.Status != domain.CertStatusActive {
		return nil, fmt.Errorf("hanya certificate berstatus active yang bisa didistribusikan (status saat ini: %s)", cert.Status)
	}

	bundle, err := s.certStore.BuildHAProxyBundle(certUUID)
	if err != nil {
		return nil, fmt.Errorf("build HAProxy bundle gagal: %w", err)
	}

	var deployments []*domain.CertDeployment
	for _, nodeID := range nodeIDs {
		d := &domain.CertDeployment{
			UUID:     uuid.NewString(),
			CertUUID: certUUID,
			NodeID:   nodeID,
			Status:   string(domain.DeployStatusPending),
		}
		if err := s.deployRepo.Create(ctx, d); err != nil {
			continue
		}

		go s.deployToNode(context.Background(), d, cert, bundle, actorID)
		deployments = append(deployments, d)
	}

	return deployments, nil
}

func (s *distributionService) DistributeToAll(ctx context.Context, certUUID string, actorID int) ([]*domain.CertDeployment, error) {
	nodes, _, err := s.nodeRepo.List(ctx, domain.ListFilter{})
	if err != nil {
		return nil, fmt.Errorf("ambil daftar node gagal: %w", err)
	}

	nodeIDs := make([]int, 0, len(nodes))
	for _, n := range nodes {
		nodeIDs = append(nodeIDs, n.ID)
	}

	return s.Distribute(ctx, certUUID, nodeIDs, actorID)
}

func (s *distributionService) deployToNode(ctx context.Context, d *domain.CertDeployment, cert *domain.Certificate, bundle string, actorID int) {
	node, err := s.nodeRepo.FindByID(ctx, d.NodeID)
	if err != nil {
		_ = s.deployRepo.UpdateStatus(ctx, d.UUID, string(domain.DeployStatusFailed), fmt.Sprintf("node tidak ditemukan: %v", err))
		return
	}

	privKey, err := security.Decrypt(node.SSHPrivateKey, s.cfg.Security.EncryptionKey)
	if err != nil {
		_ = s.deployRepo.UpdateStatus(ctx, d.UUID, string(domain.DeployStatusFailed), "dekripsi SSH key gagal")
		return
	}

	conn := &pkgssh.Connection{
		Host:       node.IPAddress,
		Port:       node.SSHPort,
		User:       node.SSHUser,
		PrivateKey: privKey,
	}

	// Simpan certificate di node: /etc/haproxy/certs/<uuid>.pem
	destPath := fmt.Sprintf("/etc/haproxy/certs/%s.pem", cert.UUID)
	if err := s.ssh.UploadFile(ctx, conn, []byte(bundle), destPath); err != nil {
		_ = s.deployRepo.UpdateStatus(ctx, d.UUID, string(domain.DeployStatusFailed), fmt.Sprintf("upload gagal: %v", err))
		return
	}

	// Set permission
	_, _ = s.ssh.RunCommand(ctx, conn, "chmod 600 "+destPath)

	// Graceful reload HAProxy (tidak restart)
	if out, err := s.ssh.RunCommand(ctx, conn, "haproxy -sf $(cat /var/run/haproxy.pid) || systemctl reload haproxy || service haproxy reload"); err != nil {
		_ = s.deployRepo.UpdateStatus(ctx, d.UUID, string(domain.DeployStatusFailed),
			fmt.Sprintf("graceful reload gagal: %v\noutput: %s", err, out))
		return
	}

	_ = s.deployRepo.UpdateStatus(ctx, d.UUID, string(domain.DeployStatusSuccess), "")

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionCertDeployed,
		ResourceType: "certificate",
		Detail:       fmt.Sprintf("Certificate %s berhasil di-deploy ke node %s", cert.Name, node.Name),
	})
}

package service

import (
	"context"
	"fmt"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/security"
	"github.com/aefw/hapm/pkg/haproxy"
	"github.com/aefw/hapm/pkg/ssh"
)

// nodeService implements domain.NodeService
type nodeService struct {
	cfg         *config.Config
	repo        domain.NodeRepository
	sshClient   ssh.Client
	provisioner haproxy.Provisioner
	auditSvc    domain.AuditService
}

// NewNodeService membuat instance NodeService baru
func NewNodeService(
	cfg *config.Config,
	repo domain.NodeRepository,
	sshClient ssh.Client,
	provisioner haproxy.Provisioner,
	auditSvc domain.AuditService,
) domain.NodeService {
	return &nodeService{
		cfg:         cfg,
		repo:        repo,
		sshClient:   sshClient,
		provisioner: provisioner,
		auditSvc:    auditSvc,
	}
}

// GetByID mengambil node berdasarkan ID (termasuk data SSH key terenkripsi)
func (s *nodeService) GetByID(ctx context.Context, id int) (*domain.Node, error) {
	node, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("node: find by id: %w", err)
	}
	// Pastikan SSH private key tidak dikembalikan ke client
	node.SSHPrivateKey = ""
	return node, nil
}

// List mengembalikan daftar ringkas semua node dengan filter dan pagination
func (s *nodeService) List(ctx context.Context, filter domain.ListFilter) ([]*domain.NodeSummary, int, error) {
	nodes, total, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("node: list: %w", err)
	}

	summaries := make([]*domain.NodeSummary, len(nodes))
	for i, n := range nodes {
		summaries[i] = &domain.NodeSummary{
			ID:                   n.ID,
			Name:                 n.Name,
			Hostname:             n.Hostname,
			IPAddress:            n.IPAddress,
			SSHPort:              n.SSHPort,
			SSHUser:              n.SSHUser,
			Status:               n.Status,
			HAProxyVersion:       n.HAProxyVersion,
			LastChecked:          n.LastChecked,
			BehindCloudflare:     n.BehindCloudflare,
			HTTPSFrontendEnabled: n.HTTPSFrontendEnabled,
		}
	}
	return summaries, total, nil
}

// Create membuat node baru, mengenkripsi SSH private key sebelum disimpan
func (s *nodeService) Create(ctx context.Context, req *domain.CreateNodeRequest, actorID int) (*domain.Node, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("node: name is required")
	}
	if req.IPAddress == "" {
		return nil, fmt.Errorf("node: ip_address is required")
	}
	if req.SSHUser == "" {
		return nil, fmt.Errorf("node: ssh_user is required")
	}
	if req.SSHPrivateKey == "" {
		return nil, fmt.Errorf("node: ssh_private_key is required")
	}

	sshPort := req.SSHPort
	if sshPort <= 0 {
		sshPort = 22
	}

	// Cek duplikat nama
	if _, err := s.repo.FindByName(ctx, req.Name); err == nil {
		return nil, fmt.Errorf("node: name already exists")
	}

	// Enkripsi SSH private key dengan AES-256-GCM
	encryptedKey, err := security.Encrypt(req.SSHPrivateKey, s.cfg.Security.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("node: encrypt ssh key: %w", err)
	}

	node := &domain.Node{
		Name:                 req.Name,
		Hostname:             req.Hostname,
		IPAddress:            req.IPAddress,
		SSHPort:              sshPort,
		SSHUser:              req.SSHUser,
		SSHPrivateKey:        encryptedKey,
		Description:          req.Description,
		Status:               domain.NodeStatusUnknown,
		BehindCloudflare:     req.BehindCloudflare,
		HTTPSFrontendEnabled: req.HTTPSFrontendEnabled,
	}

	id, err := s.repo.Create(ctx, node)
	if err != nil {
		return nil, fmt.Errorf("node: create: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionNodeCreated,
		ResourceType: "node",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Created node %s (%s)", req.Name, req.IPAddress),
	})

	created, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("node: fetch after create: %w", err)
	}
	created.SSHPrivateKey = ""
	return created, nil
}

// Update memperbarui data node, re-enkripsi SSH key jika diubah
func (s *nodeService) Update(ctx context.Context, id int, req *domain.UpdateNodeRequest, actorID int) (*domain.Node, error) {
	node, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("node: find by id: %w", err)
	}

	if req.Name != "" && req.Name != node.Name {
		if _, err := s.repo.FindByName(ctx, req.Name); err == nil {
			return nil, fmt.Errorf("node: name already exists")
		}
		node.Name = req.Name
	}
	if req.Hostname != "" {
		node.Hostname = req.Hostname
	}
	if req.IPAddress != "" {
		node.IPAddress = req.IPAddress
	}
	if req.SSHPort > 0 {
		node.SSHPort = req.SSHPort
	}
	if req.SSHUser != "" {
		node.SSHUser = req.SSHUser
	}
	if req.Description != "" {
		node.Description = req.Description
	}
	node.BehindCloudflare = req.BehindCloudflare
	node.HTTPSFrontendEnabled = req.HTTPSFrontendEnabled

	// Re-enkripsi jika SSH key baru diberikan
	if req.SSHPrivateKey != "" {
		encryptedKey, err := security.Encrypt(req.SSHPrivateKey, s.cfg.Security.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("node: encrypt ssh key: %w", err)
		}
		node.SSHPrivateKey = encryptedKey
	}

	if err := s.repo.Update(ctx, node); err != nil {
		return nil, fmt.Errorf("node: update: %w", err)
	}

	node.SSHPrivateKey = "" // hapus dari response

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionNodeUpdated,
		ResourceType: "node",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Updated node %s", node.Name),
	})

	return node, nil
}

// Delete menghapus node
func (s *nodeService) Delete(ctx context.Context, id int, actorID int) error {
	node, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("node: find by id: %w", err)
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("node: delete: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionNodeDeleted,
		ResourceType: "node",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Deleted node %s", node.Name),
	})

	return nil
}

// TestConnection mengetes koneksi SSH ke node dan mengambil versi HAProxy
func (s *nodeService) TestConnection(ctx context.Context, id int) (*domain.TestConnectionResult, error) {
	node, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("node: find by id: %w", err)
	}

	// Dekripsi SSH key
	privateKey, err := security.Decrypt(node.SSHPrivateKey, s.cfg.Security.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("SSH private key tidak bisa didekripsi: pastikan APP_ENCRYPTION_KEY sama dengan saat node ditambahkan")
	}

	conn := &ssh.Connection{
		Host:       node.IPAddress,
		Port:       node.SSHPort,
		User:       node.SSHUser,
		PrivateKey: privateKey,
	}

	// Test dengan timeout 10 detik
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	latency, err := s.sshClient.Ping(testCtx, conn)
	if err != nil {
		// Update status node menjadi offline
		_ = s.repo.UpdateStatus(ctx, id, domain.NodeStatusOffline, "")
		return &domain.TestConnectionResult{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	// Ambil versi HAProxy
	version, _ := s.provisioner.GetVersion(testCtx, conn)

	// Update status node menjadi online
	now := time.Now()
	_ = s.repo.UpdateStatus(ctx, id, domain.NodeStatusOnline, version)
	_ = node // suppress unused warning
	_ = now

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		Action:       domain.AuditActionNodeTested,
		ResourceType: "node",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Connection test to node %s: success, latency %s", node.Name, latency),
	})

	return &domain.TestConnectionResult{
		Success:        true,
		Message:        "Connection successful",
		HAProxyVersion: version,
		Latency:        latency.String(),
	}, nil
}

// Provision menginstall HAProxy pada node baru
func (s *nodeService) Provision(ctx context.Context, id int, actorID int) error {
	node, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("node: find by id: %w", err)
	}

	privateKey, err := security.Decrypt(node.SSHPrivateKey, s.cfg.Security.EncryptionKey)
	if err != nil {
		return fmt.Errorf("SSH private key tidak bisa didekripsi: pastikan APP_ENCRYPTION_KEY sama dengan saat node ditambahkan")
	}

	conn := &ssh.Connection{
		Host:       node.IPAddress,
		Port:       node.SSHPort,
		User:       node.SSHUser,
		PrivateKey: privateKey,
	}

	if err := s.provisioner.Install(ctx, conn); err != nil {
		// Gunakan %v (bukan %w) agar seluruh chain error tersimpan sebagai pesan display
		return fmt.Errorf("provision gagal: %v", err)
	}

	// Ambil versi setelah install
	version, _ := s.provisioner.GetVersion(ctx, conn)
	_ = s.repo.UpdateStatus(ctx, id, domain.NodeStatusOnline, version)

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionNodeProvisioned,
		ResourceType: "node",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Provisioned HAProxy on node %s, version: %s", node.Name, version),
	})

	return nil
}

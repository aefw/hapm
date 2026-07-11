package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/security"
	"github.com/aefw/hapm/pkg/ssh"
)

// replicationService implements domain.ReplicationService
type replicationService struct {
	cfg             *config.Config
	nodeRepo        domain.NodeRepository
	replicationRepo domain.ReplicationRepository
	driftRepo       domain.DriftRepository
	configSvc       domain.ConfigService
	sshClient       ssh.Client
	auditSvc        domain.AuditService
}

// NewReplicationService membuat instance ReplicationService baru
func NewReplicationService(
	cfg *config.Config,
	nodeRepo domain.NodeRepository,
	replicationRepo domain.ReplicationRepository,
	driftRepo domain.DriftRepository,
	configSvc domain.ConfigService,
	sshClient ssh.Client,
	auditSvc domain.AuditService,
) domain.ReplicationService {
	return &replicationService{
		cfg:             cfg,
		nodeRepo:        nodeRepo,
		replicationRepo: replicationRepo,
		driftRepo:       driftRepo,
		configSvc:       configSvc,
		sshClient:       sshClient,
		auditSvc:        auditSvc,
	}
}

// ListTargets mengembalikan semua replication targets
func (s *replicationService) ListTargets(ctx context.Context) ([]*domain.ReplicationTarget, error) {
	targets, err := s.replicationRepo.ListTargets(ctx)
	if err != nil {
		return nil, fmt.Errorf("replication: list targets: %w", err)
	}
	return targets, nil
}

// CreateTarget membuat replication target baru
func (s *replicationService) CreateTarget(ctx context.Context, req *domain.CreateReplicationTargetRequest, actorID int) (*domain.ReplicationTarget, error) {
	// Validasi node source ada
	if _, err := s.nodeRepo.FindByID(ctx, req.SourceNodeID); err != nil {
		return nil, fmt.Errorf("replication: source node not found")
	}
	// Validasi node target ada
	if _, err := s.nodeRepo.FindByID(ctx, req.TargetNodeID); err != nil {
		return nil, fmt.Errorf("replication: target node not found")
	}
	// Source dan target tidak boleh sama
	if req.SourceNodeID == req.TargetNodeID {
		return nil, fmt.Errorf("replication: source and target node cannot be the same")
	}

	target := &domain.ReplicationTarget{
		SourceNodeID:  req.SourceNodeID,
		TargetNodeID:  req.TargetNodeID,
		SyncFrontends: req.SyncFrontends,
		SyncBackends:  req.SyncBackends,
		SyncSSL:       req.SyncSSL,
		SyncMaps:      req.SyncMaps,
		Enabled:       req.Enabled,
	}

	id, err := s.replicationRepo.CreateTarget(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("replication: create target: %w", err)
	}
	target.ID = id

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionReplicationPushed,
		ResourceType: "replication_target",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Created replication target: node %d → node %d", req.SourceNodeID, req.TargetNodeID),
	})

	return target, nil
}

// UpdateTarget memperbarui replication target
func (s *replicationService) UpdateTarget(ctx context.Context, id int, req *domain.CreateReplicationTargetRequest, actorID int) (*domain.ReplicationTarget, error) {
	target, err := s.replicationRepo.FindTargetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("replication: find target by id: %w", err)
	}

	target.SyncFrontends = req.SyncFrontends
	target.SyncBackends = req.SyncBackends
	target.SyncSSL = req.SyncSSL
	target.SyncMaps = req.SyncMaps
	target.Enabled = req.Enabled

	if err := s.replicationRepo.UpdateTarget(ctx, target); err != nil {
		return nil, fmt.Errorf("replication: update target: %w", err)
	}

	return target, nil
}

// DeleteTarget menghapus replication target
func (s *replicationService) DeleteTarget(ctx context.Context, id int, actorID int) error {
	if err := s.replicationRepo.DeleteTarget(ctx, id); err != nil {
		return fmt.Errorf("replication: delete target: %w", err)
	}
	return nil
}

// PushReplication mendorong konfigurasi dari source ke target node
func (s *replicationService) PushReplication(ctx context.Context, targetID int, actorID int) (*domain.ReplicationJob, error) {
	target, err := s.replicationRepo.FindTargetByID(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("replication: find target: %w", err)
	}
	if !target.Enabled {
		return nil, fmt.Errorf("replication: target is disabled")
	}

	// Buat record job
	now := time.Now()
	job := &domain.ReplicationJob{
		ReplicationID: targetID,
		UserID:        &actorID,
		Status:        "running",
		StartedAt:     &now,
	}

	jobID, err := s.replicationRepo.CreateJob(ctx, job)
	if err != nil {
		return nil, fmt.Errorf("replication: create job: %w", err)
	}
	job.ID = jobID

	// Jalankan replikasi secara asinkron
	go s.executePush(context.Background(), job, target)

	return job, nil
}

// executePush menjalankan proses replikasi dari source ke target node
func (s *replicationService) executePush(ctx context.Context, job *domain.ReplicationJob, target *domain.ReplicationTarget) {
	updateJob := func(status, errMsg string) {
		_ = s.replicationRepo.UpdateJobStatus(ctx, job.ID, status, errMsg)
	}

	// Generate config dari source node
	generated, err := s.configSvc.GenerateForNode(ctx, target.SourceNodeID)
	if err != nil {
		updateJob("failed", fmt.Sprintf("generate config: %v", err))
		return
	}

	// Ambil info target node
	targetNode, err := s.nodeRepo.FindByID(ctx, target.TargetNodeID)
	if err != nil {
		updateJob("failed", fmt.Sprintf("find target node: %v", err))
		return
	}

	// Dekripsi SSH key target
	privateKey, err := security.Decrypt(targetNode.SSHPrivateKey, s.cfg.Security.EncryptionKey)
	if err != nil {
		updateJob("failed", "failed to decrypt ssh key")
		return
	}

	conn := &ssh.Connection{
		Host:       targetNode.IPAddress,
		Port:       targetNode.SSHPort,
		User:       targetNode.SSHUser,
		PrivateKey: privateKey,
	}

	// Upload konfigurasi ke target node
	if err := s.sshClient.UploadFile(ctx, conn, []byte(generated.Content), "/etc/haproxy/haproxy.cfg"); err != nil {
		updateJob("failed", fmt.Sprintf("upload config: %v", err))
		return
	}

	// Reload HAProxy pada target node
	if _, err := s.sshClient.RunCommand(ctx, conn, "systemctl reload haproxy"); err != nil {
		updateJob("failed", fmt.Sprintf("reload haproxy: %v", err))
		return
	}

	updateJob("success", "")

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       job.UserID,
		Action:       domain.AuditActionReplicationPushed,
		ResourceType: "replication_job",
		ResourceID:   &job.ID,
		Detail:       fmt.Sprintf("Replication pushed: node %d → node %d", target.SourceNodeID, target.TargetNodeID),
	})
}

// CheckDrift memeriksa drift konfigurasi pada semua node (live vs database)
func (s *replicationService) CheckDrift(ctx context.Context) ([]*domain.DriftReport, error) {
	nodes, _, err := s.nodeRepo.List(ctx, domain.ListFilter{})
	if err != nil {
		return nil, fmt.Errorf("replication: list nodes: %w", err)
	}

	var reports []*domain.DriftReport

	for _, node := range nodes {
		report, err := s.checkNodeDrift(ctx, node)
		if err != nil {
			// Skip node yang tidak bisa diperiksa (offline, dll)
			continue
		}
		reports = append(reports, report)
	}

	return reports, nil
}

// checkNodeDrift memeriksa drift untuk satu node
func (s *replicationService) checkNodeDrift(ctx context.Context, node *domain.Node) (*domain.DriftReport, error) {
	// Generate config dari DB
	generated, err := s.configSvc.GenerateForNode(ctx, node.ID)
	if err != nil {
		return nil, fmt.Errorf("drift: generate config for node %d: %w", node.ID, err)
	}
	dbHash := generated.Hash

	// Ambil config live dari node via SSH
	privateKey, err := security.Decrypt(node.SSHPrivateKey, s.cfg.Security.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("drift: decrypt ssh key: %w", err)
	}

	conn := &ssh.Connection{
		Host:       node.IPAddress,
		Port:       node.SSHPort,
		User:       node.SSHUser,
		PrivateKey: privateKey,
	}

	liveContent, err := s.sshClient.DownloadFile(ctx, conn, "/etc/haproxy/haproxy.cfg")
	if err != nil {
		return nil, fmt.Errorf("drift: download live config: %w", err)
	}

	// Hitung hash config live
	h := sha256.Sum256(liveContent)
	liveHash := hex.EncodeToString(h[:])

	driftDetected := liveHash != dbHash
	checkedAt := time.Now()

	report := &domain.DriftReport{
		NodeID:         node.ID,
		NodeName:       node.Name,
		LiveConfigHash: liveHash,
		DBConfigHash:   dbHash,
		DriftDetected:  driftDetected,
		CheckedAt:      checkedAt,
	}

	// Simpan laporan
	_, _ = s.driftRepo.Create(ctx, report)

	return report, nil
}

package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/security"
	"github.com/aefw/hapm/pkg/haproxy"
	"github.com/aefw/hapm/pkg/ssh"
	"github.com/aefw/hapm/pkg/storage"
)

// deployService implements domain.DeployService
type deployService struct {
	cfg          *config.Config
	nodeRepo     domain.NodeRepository
	domainRepo   domain.DomainRepository
	certRepo     domain.CertificateRepository
	certStore    *storage.CertStore
	configSvc    domain.ConfigService
	revisionRepo domain.RevisionRepository
	deployRepo   domain.DeploymentRepository
	sshClient    ssh.Client
	validator    haproxy.Validator
	auditSvc     domain.AuditService
}

// NewDeployService membuat instance DeployService baru
func NewDeployService(
	cfg *config.Config,
	nodeRepo domain.NodeRepository,
	domainRepo domain.DomainRepository,
	certRepo domain.CertificateRepository,
	certStore *storage.CertStore,
	configSvc domain.ConfigService,
	revisionRepo domain.RevisionRepository,
	deployRepo domain.DeploymentRepository,
	sshClient ssh.Client,
	validator haproxy.Validator,
	auditSvc domain.AuditService,
) domain.DeployService {
	return &deployService{
		cfg:          cfg,
		nodeRepo:     nodeRepo,
		domainRepo:   domainRepo,
		certRepo:     certRepo,
		certStore:    certStore,
		configSvc:    configSvc,
		revisionRepo: revisionRepo,
		deployRepo:   deployRepo,
		sshClient:    sshClient,
		validator:    validator,
		auditSvc:     auditSvc,
	}
}

// Deploy menjalankan pipeline deployment: generate → validate → backup → upload → reload → verify
func (s *deployService) Deploy(ctx context.Context, req *domain.DeployRequest) (*domain.Deployment, error) {
	// Buat record deployment
	now := time.Now()
	deployment := &domain.Deployment{
		NodeID:    req.NodeID,
		UserID:    req.UserID,
		Status:    domain.DeployStatusPending,
		Stage:     domain.DeployStageGenerate,
		StartedAt: &now,
	}

	id, err := s.deployRepo.Create(ctx, deployment)
	if err != nil {
		return nil, fmt.Errorf("deploy: create deployment record: %w", err)
	}
	deployment.ID = id

	// Jalankan pipeline secara asinkron agar endpoint tidak block
	go s.runPipeline(context.Background(), deployment, req)

	// Re-fetch untuk dapat timestamps dari DB
	if fetched, err := s.deployRepo.FindByID(ctx, id); err == nil {
		deployment = fetched
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &req.UserID,
		Action:       domain.AuditActionDeployStarted,
		ResourceType: "deployment",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Deploy started for node %d", req.NodeID),
	})

	return deployment, nil
}

// runPipeline menjalankan seluruh tahap deployment secara berurutan
func (s *deployService) runPipeline(ctx context.Context, deployment *domain.Deployment, req *domain.DeployRequest) {
	nodeID := req.NodeID
	deployID := deployment.ID
	userID := req.UserID

	// Helper: update status
	updateStatus := func(status domain.DeployStatus, stage domain.DeployStage, errMsg string) {
		_ = s.deployRepo.UpdateStatus(ctx, deployID, status, stage, errMsg)
	}

	// ── Stage 1: Generate konfigurasi ──────────────────────────────
	updateStatus(domain.DeployStatusRunning, domain.DeployStageGenerate, "")

	generated, err := s.configSvc.GenerateForNode(ctx, nodeID)
	if err != nil {
		updateStatus(domain.DeployStatusFailed, domain.DeployStageGenerate, err.Error())
		s.logAuditFail(ctx, deployID, userID, nodeID, "generate", err)
		return
	}

	// ── Stage 2: Validate konfigurasi ──────────────────────────────
	updateStatus(domain.DeployStatusRunning, domain.DeployStageValidate, "")

	node, err := s.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		updateStatus(domain.DeployStatusFailed, domain.DeployStageValidate, err.Error())
		return
	}

	privateKey, err := security.Decrypt(node.SSHPrivateKey, s.cfg.Security.EncryptionKey)
	if err != nil {
		updateStatus(domain.DeployStatusFailed, domain.DeployStageValidate, "failed to decrypt ssh key")
		return
	}

	conn := &ssh.Connection{
		Host:       node.IPAddress,
		Port:       node.SSHPort,
		User:       node.SSHUser,
		PrivateKey: privateKey,
	}

	// Pastikan direktori map dan certs ada di node sebelum validasi
	_, _ = s.sshClient.RunCommand(ctx, conn,
		"sudo mkdir -p /etc/haproxy/map && { [ -f /etc/haproxy/map/hosts ] || sudo touch /etc/haproxy/map/hosts; }")
	_, _ = s.sshClient.RunCommand(ctx, conn,
		"sudo mkdir -p /etc/haproxy/certs && sudo chmod 700 /etc/haproxy/certs")

	// Push semua cert aktif yang dipakai domain ke node (agar haproxy -c dan reload tidak gagal)
	s.pushCertsToNode(ctx, conn)

	valid, validErrMsg, err := s.validator.Validate(ctx, conn, generated.Content)
	if err != nil || !valid {
		msg := validErrMsg
		if err != nil {
			msg = err.Error()
		}
		updateStatus(domain.DeployStatusFailed, domain.DeployStageValidate, msg)
		s.logAuditFail(ctx, deployID, userID, nodeID, "validate", fmt.Errorf(msg))
		return
	}

	// ── Stage 3: Backup konfigurasi lama ───────────────────────────
	updateStatus(domain.DeployStatusRunning, domain.DeployStageBackup, "")

	backupPath := fmt.Sprintf("/etc/haproxy/haproxy.cfg.bak.%d", time.Now().Unix())
	if _, err := s.sshClient.RunCommand(ctx, conn,
		fmt.Sprintf("sudo cp /etc/haproxy/haproxy.cfg %s 2>/dev/null", backupPath)); err != nil {
		// Backup gagal — catat tapi lanjutkan; rollback tidak akan tersedia jika deploy gagal
		_ = s.deployRepo.UpdateStatus(ctx, deployID, domain.DeployStatusRunning, domain.DeployStageBackup,
			fmt.Sprintf("warning: backup gagal (lanjut tanpa backup): %v", err))
		backupPath = ""
	}

	// ── Stage 4: Upload konfigurasi baru ───────────────────────────
	// Upload ke /tmp terlebih dahulu (user-writable), lalu sudo mv ke /etc/haproxy/
	updateStatus(domain.DeployStatusRunning, domain.DeployStageUpload, "")

	// Pastikan direktori map ada di node
	if _, err := s.sshClient.RunCommand(ctx, conn, "sudo mkdir -p /etc/haproxy/map"); err != nil {
		updateStatus(domain.DeployStatusFailed, domain.DeployStageUpload,
			fmt.Sprintf("gagal membuat direktori /etc/haproxy/map: %v", err))
		s.logAuditFail(ctx, deployID, userID, nodeID, "upload-mkdir-map", err)
		return
	}

	// Upload haproxy.cfg
	tmpPath := "/tmp/hapm_haproxy.cfg"
	if err := s.sshClient.UploadFile(ctx, conn, []byte(generated.Content), tmpPath); err != nil {
		updateStatus(domain.DeployStatusFailed, domain.DeployStageUpload,
			fmt.Sprintf("gagal upload config ke node: %v", err))
		s.logAuditFail(ctx, deployID, userID, nodeID, "upload", err)
		return
	}

	// Upload hosts.map
	tmpMapPath := "/tmp/hapm_hosts.map"
	if err := s.sshClient.UploadFile(ctx, conn, []byte(generated.HostsMap), tmpMapPath); err != nil {
		updateStatus(domain.DeployStatusFailed, domain.DeployStageUpload,
			fmt.Sprintf("gagal upload hosts.map ke node: %v", err))
		s.logAuditFail(ctx, deployID, userID, nodeID, "upload-map", err)
		return
	}

	// Pindahkan config dan map dari /tmp ke lokasi HAProxy dengan sudo
	mvCmd := fmt.Sprintf(
		"sudo mv %s /etc/haproxy/haproxy.cfg && sudo chmod 640 /etc/haproxy/haproxy.cfg && "+
			"sudo mv %s /etc/haproxy/map/hosts && sudo chmod 640 /etc/haproxy/map/hosts",
		tmpPath, tmpMapPath,
	)
	if out, err := s.sshClient.RunCommand(ctx, conn, mvCmd); err != nil {
		updateStatus(domain.DeployStatusFailed, domain.DeployStageUpload,
			fmt.Sprintf("gagal memindahkan config ke /etc/haproxy/ (pastikan user SSH punya sudo NOPASSWD): %v — %s", err, out))
		s.logAuditFail(ctx, deployID, userID, nodeID, "upload-move", err)
		return
	}

	// ── Stage 5: Reload HAProxy ─────────────────────────────────────
	updateStatus(domain.DeployStatusRunning, domain.DeployStageReload, "")

	// rollback helper — hanya jalan jika ada backup
	doRollback := func() {
		if backupPath == "" {
			return
		}
		updateStatus(domain.DeployStatusRunning, domain.DeployStageRollback, "")
		_, _ = s.sshClient.RunCommand(ctx, conn,
			fmt.Sprintf("sudo cp %s /etc/haproxy/haproxy.cfg && sudo systemctl reload haproxy", backupPath))
	}

	reloadOut, err := s.sshClient.RunCommand(ctx, conn, "sudo systemctl reload haproxy 2>&1")
	if err != nil {
		doRollback()
		updateStatus(domain.DeployStatusRolledBack, domain.DeployStageRollback,
			fmt.Sprintf("reload gagal: %s", reloadOut))
		s.logAuditFail(ctx, deployID, userID, nodeID, "reload", err)
		return
	}

	// ── Stage 6: Verify HAProxy aktif ──────────────────────────────
	updateStatus(domain.DeployStatusRunning, domain.DeployStageVerify, "")

	time.Sleep(2 * time.Second)
	statusOut, _ := s.sshClient.RunCommand(ctx, conn, "systemctl is-active haproxy 2>&1")
	if strings.TrimSpace(statusOut) != "active" {
		doRollback()
		updateStatus(domain.DeployStatusRolledBack, domain.DeployStageRollback,
			fmt.Sprintf("haproxy tidak aktif setelah reload: %s", statusOut))
		return
	}

	// ── Simpan revision di DB ───────────────────────────────────────
	_ = s.saveRevision(ctx, nodeID, userID, generated.Content, req.Comment)

	// ── Deployment sukses ───────────────────────────────────────────
	updateStatus(domain.DeployStatusSuccess, domain.DeployStageVerify, "")

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &userID,
		Action:       domain.AuditActionDeploySuccess,
		ResourceType: "deployment",
		ResourceID:   &deployID,
		Detail:       fmt.Sprintf("Deploy success for node %d, hash: %s", nodeID, generated.Hash),
	})
}

// saveRevision menyimpan konfigurasi yang berhasil di-deploy sebagai revisi baru
func (s *deployService) saveRevision(ctx context.Context, nodeID, userID int, content, comment string) error {
	nextNum, err := s.revisionRepo.NextRevisionNumber(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("saveRevision: next number: %w", err)
	}
	rev := &domain.ConfigRevision{
		NodeID:         nodeID,
		RevisionNumber: nextNum,
		ConfigContent:  content,
		Comment:        comment,
		UserID:         userID,
		Deployed:       true,
	}
	id, err := s.revisionRepo.Create(ctx, rev)
	if err != nil {
		return fmt.Errorf("saveRevision: create: %w", err)
	}
	return s.revisionRepo.MarkDeployed(ctx, id)
}

// pushCertsToNode mendistribusikan semua SSL cert aktif yang dipakai domain ke node.
// Non-fatal: error dicatat sebagai log warning agar haproxy -c bisa mendeteksi masalah cert secara eksplisit.
func (s *deployService) pushCertsToNode(ctx context.Context, conn *ssh.Connection) {
	if s.domainRepo == nil || s.certRepo == nil || s.certStore == nil {
		return
	}

	domains, err := s.domainRepo.ListEnabled(ctx)
	if err != nil {
		log.Printf("[WARN] pushCertsToNode: gagal ambil domain list: %v", err)
		return
	}

	certUUIDs := collectCertUUIDs(domains)
	if len(certUUIDs) == 0 {
		return
	}

	for _, uuid := range certUUIDs {
		cert, err := s.certRepo.FindByUUID(ctx, uuid)
		if err != nil || cert.Status != domain.CertStatusActive {
			continue
		}

		bundle, err := s.certStore.BuildHAProxyBundle(uuid)
		if err != nil {
			log.Printf("[WARN] pushCertsToNode: build bundle cert %s gagal: %v", uuid, err)
			continue
		}

		destPath := fmt.Sprintf("/etc/haproxy/certs/%s.pem", uuid)
		if err := s.sshClient.UploadFile(ctx, conn, []byte(bundle), destPath); err != nil {
			log.Printf("[WARN] pushCertsToNode: upload cert %s gagal: %v", uuid, err)
			continue
		}
		_, _ = s.sshClient.RunCommand(ctx, conn, "sudo chmod 600 "+destPath)
		log.Printf("[INFO] pushCertsToNode: cert %s berhasil di-push ke node", uuid)
	}
}

// logAuditFail mencatat audit log untuk kegagalan deployment
func (s *deployService) logAuditFail(ctx context.Context, deployID, userID, nodeID int, stage string, err error) {
	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &userID,
		Action:       domain.AuditActionDeployFailed,
		ResourceType: "deployment",
		ResourceID:   &deployID,
		Detail:       fmt.Sprintf("Deploy failed at stage %s for node %d: %v", stage, nodeID, err),
	})
}

// GetStatus mengambil status deployment berdasarkan ID
func (s *deployService) GetStatus(ctx context.Context, deployID int) (*domain.Deployment, error) {
	d, err := s.deployRepo.FindByID(ctx, deployID)
	if err != nil {
		return nil, fmt.Errorf("deploy: find by id: %w", err)
	}
	return d, nil
}

// ListByNode mengembalikan daftar deployment untuk node tertentu
func (s *deployService) ListByNode(ctx context.Context, nodeID int, limit int) ([]*domain.Deployment, error) {
	if limit <= 0 {
		limit = 20
	}
	deployments, err := s.deployRepo.ListByNode(ctx, nodeID, limit)
	if err != nil {
		return nil, fmt.Errorf("deploy: list by node: %w", err)
	}
	return deployments, nil
}

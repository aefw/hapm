package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/pkg/acme"
	"github.com/aefw/hapm/pkg/storage"
	"github.com/google/uuid"
)

var domainRe = regexp.MustCompile(
	`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`,
)

func isValidCertDomain(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	return domainRe.MatchString(name)
}

// certificateService implements domain.CertificateService
type certificateService struct {
	cfg         *config.Config
	certRepo    domain.CertificateRepository
	jobRepo     domain.CertJobRepository
	settingsSvc domain.SettingsService
	acmeClient  *acme.Client
	certStore   *storage.CertStore
	auditSvc    domain.AuditService
}

func NewCertificateService(
	cfg *config.Config,
	certRepo domain.CertificateRepository,
	jobRepo domain.CertJobRepository,
	settingsSvc domain.SettingsService,
	acmeClient *acme.Client,
	certStore *storage.CertStore,
	auditSvc domain.AuditService,
) domain.CertificateService {
	return &certificateService{
		cfg: cfg, certRepo: certRepo, jobRepo: jobRepo,
		settingsSvc: settingsSvc, acmeClient: acmeClient,
		certStore: certStore, auditSvc: auditSvc,
	}
}

func (s *certificateService) GetByUUID(ctx context.Context, id string) (*domain.Certificate, error) {
	return s.certRepo.FindByUUID(ctx, id)
}

func (s *certificateService) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Certificate, int, error) {
	return s.certRepo.List(ctx, filter)
}

func (s *certificateService) Create(ctx context.Context, req *domain.CreateCertRequest, actorID int) (*domain.Certificate, error) {
	if err := validateCreateCertRequest(req); err != nil {
		return nil, err
	}

	if _, err := s.certRepo.FindByName(ctx, req.Name); err == nil {
		return nil, errors.New("certificate name sudah ada")
	}

	primaryDomain := req.Domains[0]
	allDomains := req.Domains
	san := req.Domains[1:]
	if san == nil {
		san = []string{}
	}

	renewBefore := req.RenewBefore
	if renewBefore <= 0 {
		renewBefore = 30
	}

	cert := &domain.Certificate{
		UUID:          uuid.NewString(),
		Name:          req.Name,
		Provider:      req.Provider,
		Challenge:     req.Challenge,
		Status:        domain.CertStatusPending,
		PrimaryDomain: primaryDomain,
		Domains:       allDomains,
		SAN:           san,
		Zone:          req.Zone,
		DNSProvider:   req.DNSProvider,
		RenewBefore:   renewBefore,
		AutoRenew:     req.AutoRenew,
	}

	if err := s.certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("simpan certificate gagal: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionCertCreated,
		ResourceType: "certificate",
		Detail:       fmt.Sprintf("Certificate %s dibuat untuk domain %s", req.Name, primaryDomain),
	})

	return cert, nil
}

func (s *certificateService) Update(ctx context.Context, id string, req *domain.CreateCertRequest, actorID int) (*domain.Certificate, error) {
	cert, err := s.certRepo.FindByUUID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Name != cert.Name {
		if _, err := s.certRepo.FindByName(ctx, req.Name); err == nil {
			return nil, errors.New("certificate name sudah ada")
		}
	}

	cert.Name = req.Name
	cert.AutoRenew = req.AutoRenew
	cert.RenewBefore = req.RenewBefore
	if cert.RenewBefore <= 0 {
		cert.RenewBefore = 30
	}

	if err := s.certRepo.Update(ctx, cert); err != nil {
		return nil, fmt.Errorf("update certificate gagal: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionCertUpdated,
		ResourceType: "certificate",
		Detail:       fmt.Sprintf("Certificate %s diperbarui", cert.Name),
	})

	return cert, nil
}

func (s *certificateService) Upload(ctx context.Context, req *domain.UploadCertRequest, actorID int) (*domain.Certificate, error) {
	if req.Name == "" {
		return nil, errors.New("name wajib diisi")
	}
	if req.CertPEM == "" {
		return nil, errors.New("certificate_pem wajib diisi")
	}
	if req.KeyPEM == "" {
		return nil, errors.New("private_key_pem wajib diisi")
	}

	if _, err := s.certRepo.FindByName(ctx, req.Name); err == nil {
		return nil, errors.New("certificate name sudah ada")
	}

	certUUID := uuid.NewString()

	fingerprint, notBefore, notAfter, err := s.certStore.SaveManual(
		certUUID, req.CertPEM, req.KeyPEM, req.ChainPEM,
	)
	if err != nil {
		return nil, fmt.Errorf("simpan file certificate gagal: %w", err)
	}

	// Ekstrak primary domain dari SAN cert
	primaryDomain := extractPrimaryDomain(req.CertPEM)
	domains := extractAllDomains(req.CertPEM)
	san := []string{}
	if len(domains) > 1 {
		san = domains[1:]
	}

	cert := &domain.Certificate{
		UUID:          certUUID,
		Name:          req.Name,
		Provider:      domain.CertProviderManual,
		Challenge:     domain.CertChallengeNone,
		Status:        domain.CertStatusActive,
		PrimaryDomain: primaryDomain,
		Domains:       domains,
		SAN:           san,
		Fingerprint:   fingerprint,
		AutoRenew:     req.AutoRenew,
		RenewBefore:   30,
	}
	if notBefore != nil {
		cert.IssuedAt = notBefore
	}
	if notAfter != nil {
		cert.ExpiresAt = notAfter
	}

	if err := s.certRepo.Create(ctx, cert); err != nil {
		_ = s.certStore.Remove(certUUID)
		return nil, fmt.Errorf("simpan certificate ke DB gagal: %w", err)
	}

	_ = s.certStore.WriteMeta(certUUID, &storage.CertMetadata{
		UUID:        certUUID,
		Provider:    string(domain.CertProviderManual),
		Challenge:   string(domain.CertChallengeNone),
		Domains:     domains,
		Fingerprint: fingerprint,
		Status:      string(domain.CertStatusActive),
	})

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionCertUploaded,
		ResourceType: "certificate",
		Detail:       fmt.Sprintf("Certificate manual %s diupload untuk %s", req.Name, primaryDomain),
	})

	return cert, nil
}

func (s *certificateService) Delete(ctx context.Context, id string, actorID int) error {
	cert, err := s.certRepo.FindByUUID(ctx, id)
	if err != nil {
		return err
	}

	// Lock sebelum hapus agar tidak ada proses yang sedang berjalan
	locked, err := s.certRepo.Lock(ctx, id)
	if err != nil || !locked {
		return errors.New("certificate sedang diproses, coba lagi nanti")
	}
	defer s.certRepo.Unlock(ctx, id)

	if err := s.certRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("hapus certificate gagal: %w", err)
	}

	_ = s.certStore.Remove(id)

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionCertDeleted,
		ResourceType: "certificate",
		Detail:       fmt.Sprintf("Certificate %s dihapus", cert.Name),
	})

	return nil
}

func (s *certificateService) Issue(ctx context.Context, id string, actorID int) (*domain.CertJob, error) {
	cert, err := s.certRepo.FindByUUID(ctx, id)
	if err != nil {
		return nil, err
	}
	if cert.Provider == domain.CertProviderManual {
		return nil, errors.New("certificate manual tidak bisa di-issue via ACME")
	}

	locked, err := s.certRepo.Lock(ctx, id)
	if err != nil || !locked {
		return nil, errors.New("certificate sedang diproses oleh proses lain")
	}

	job := &domain.CertJob{
		UUID:     uuid.NewString(),
		CertUUID: id,
		JobType:  domain.JobTypeIssue,
		Status:   domain.JobStatusPending,
	}
	if err := s.jobRepo.Create(ctx, job); err != nil {
		s.certRepo.Unlock(ctx, id)
		return nil, fmt.Errorf("buat job gagal: %w", err)
	}

	cert.Status = domain.CertStatusIssuing
	cert.ErrorMessage = ""
	_ = s.certRepo.Update(ctx, cert)

	go s.runIssueJob(context.Background(), cert, job.UUID, actorID)

	return job, nil
}

func (s *certificateService) runIssueJob(ctx context.Context, cert *domain.Certificate, jobUUID string, actorID int) {
	defer s.certRepo.Unlock(ctx, cert.UUID)

	_ = s.jobRepo.UpdateStatus(ctx, jobUUID, domain.JobStatusRunning, "", "")

	cfToken, _ := s.settingsSvc.GetCloudflareToken(ctx)
	email, _ := s.settingsSvc.GetACMEEmail(ctx)
	staging, _ := s.settingsSvc.IsACMEStaging(ctx)

	req := &acme.IssueRequest{
		JobUUID:     jobUUID,
		CertUUID:    cert.UUID,
		Domains:     cert.Domains,
		Challenge:   string(cert.Challenge),
		CFToken:     cfToken,
		Email:       email,
		Staging:     staging,
		StoragePath: s.certStore.LegoDir(cert.UUID),
		WebRootPath: s.cfg.CMC.WebRootPath,
	}

	resp, err := s.acmeClient.Issue(ctx, req)
	if err != nil {
		errMsg := err.Error()
		logs := ""
		if resp != nil {
			logs = resp.Logs
		}
		_ = s.jobRepo.UpdateStatus(ctx, jobUUID, domain.JobStatusFailed, logs, errMsg)
		cert.Status = domain.CertStatusError
		cert.ErrorMessage = errMsg
		_ = s.certRepo.Update(ctx, cert)
		_ = s.auditSvc.Log(ctx, &domain.AuditLog{
			UserID:       &actorID,
			Action:       domain.AuditActionCertIssueFailed,
			ResourceType: "certificate",
			Detail:       fmt.Sprintf("Issue certificate %s gagal: %s", cert.Name, errMsg),
		})
		return
	}

	// Ambil cert dari storage LEGO
	fingerprint, notBefore, notAfter, parseErr := s.certStore.SaveLEGO(
		cert.UUID, s.certStore.LegoDir(cert.UUID), cert.PrimaryDomain,
	)
	if parseErr != nil {
		_ = s.jobRepo.UpdateStatus(ctx, jobUUID, domain.JobStatusFailed, resp.Logs, parseErr.Error())
		cert.Status = domain.CertStatusError
		cert.ErrorMessage = parseErr.Error()
		_ = s.certRepo.Update(ctx, cert)
		return
	}

	cert.Status = domain.CertStatusActive
	cert.Fingerprint = fingerprint
	cert.ErrorMessage = ""
	if notBefore != nil {
		cert.IssuedAt = notBefore
	}
	if notAfter != nil {
		cert.ExpiresAt = notAfter
	}
	_ = s.certRepo.Update(ctx, cert)
	_ = s.jobRepo.UpdateStatus(ctx, jobUUID, domain.JobStatusSuccess, resp.Logs, "")

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionCertIssued,
		ResourceType: "certificate",
		Detail:       fmt.Sprintf("Certificate %s berhasil diterbitkan", cert.Name),
	})
}

func (s *certificateService) Renew(ctx context.Context, id string, actorID int) (*domain.CertJob, error) {
	cert, err := s.certRepo.FindByUUID(ctx, id)
	if err != nil {
		return nil, err
	}
	if cert.Provider == domain.CertProviderManual {
		return nil, errors.New("certificate manual tidak bisa di-renew via ACME, gunakan upload ulang")
	}

	locked, err := s.certRepo.Lock(ctx, id)
	if err != nil || !locked {
		return nil, errors.New("certificate sedang diproses oleh proses lain")
	}

	job := &domain.CertJob{
		UUID:     uuid.NewString(),
		CertUUID: id,
		JobType:  domain.JobTypeRenew,
		Status:   domain.JobStatusPending,
	}
	if err := s.jobRepo.Create(ctx, job); err != nil {
		s.certRepo.Unlock(ctx, id)
		return nil, fmt.Errorf("buat job gagal: %w", err)
	}

	go s.runRenewJob(context.Background(), cert, job.UUID, actorID)

	return job, nil
}

func (s *certificateService) runRenewJob(ctx context.Context, cert *domain.Certificate, jobUUID string, actorID int) {
	defer s.certRepo.Unlock(ctx, cert.UUID)

	_ = s.jobRepo.UpdateStatus(ctx, jobUUID, domain.JobStatusRunning, "", "")

	cfToken, _ := s.settingsSvc.GetCloudflareToken(ctx)
	email, _ := s.settingsSvc.GetACMEEmail(ctx)
	staging, _ := s.settingsSvc.IsACMEStaging(ctx)

	req := &acme.RenewRequest{
		JobUUID:     jobUUID,
		CertUUID:    cert.UUID,
		Domains:     cert.Domains,
		Challenge:   string(cert.Challenge),
		CFToken:     cfToken,
		Email:       email,
		Staging:     staging,
		StoragePath: s.certStore.LegoDir(cert.UUID),
		WebRootPath: s.cfg.CMC.WebRootPath,
	}

	resp, err := s.acmeClient.Renew(ctx, req)
	if err != nil {
		errMsg := err.Error()
		logs := ""
		if resp != nil {
			logs = resp.Logs
		}
		_ = s.jobRepo.UpdateStatus(ctx, jobUUID, domain.JobStatusFailed, logs, errMsg)
		cert.ErrorMessage = errMsg
		_ = s.certRepo.Update(ctx, cert)
		_ = s.auditSvc.Log(ctx, &domain.AuditLog{
			UserID:       &actorID,
			Action:       domain.AuditActionCertRenewFailed,
			ResourceType: "certificate",
			Detail:       fmt.Sprintf("Renew certificate %s gagal: %s", cert.Name, errMsg),
		})
		return
	}

	fingerprint, notBefore, notAfter, parseErr := s.certStore.SaveLEGO(
		cert.UUID, s.certStore.LegoDir(cert.UUID), cert.PrimaryDomain,
	)
	if parseErr != nil {
		_ = s.jobRepo.UpdateStatus(ctx, jobUUID, domain.JobStatusFailed, resp.Logs, parseErr.Error())
		return
	}

	cert.Status = domain.CertStatusActive
	cert.Fingerprint = fingerprint
	cert.ErrorMessage = ""
	if notBefore != nil {
		cert.IssuedAt = notBefore
	}
	if notAfter != nil {
		cert.ExpiresAt = notAfter
	}
	_ = s.certRepo.Update(ctx, cert)
	_ = s.jobRepo.UpdateStatus(ctx, jobUUID, domain.JobStatusSuccess, resp.Logs, "")

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionCertRenewed,
		ResourceType: "certificate",
		Detail:       fmt.Sprintf("Certificate %s berhasil diperpanjang", cert.Name),
	})
}

func (s *certificateService) Revoke(ctx context.Context, id string, actorID int) error {
	cert, err := s.certRepo.FindByUUID(ctx, id)
	if err != nil {
		return err
	}
	if cert.Provider == domain.CertProviderManual {
		return errors.New("certificate manual tidak perlu revoke via ACME")
	}

	locked, err := s.certRepo.Lock(ctx, id)
	if err != nil || !locked {
		return errors.New("certificate sedang diproses oleh proses lain")
	}
	defer s.certRepo.Unlock(ctx, id)

	email, _ := s.settingsSvc.GetACMEEmail(ctx)
	staging, _ := s.settingsSvc.IsACMEStaging(ctx)

	req := &acme.RevokeRequest{
		CertUUID:    cert.UUID,
		Domain:      cert.PrimaryDomain,
		Email:       email,
		Staging:     staging,
		StoragePath: s.certStore.LegoDir(cert.UUID),
	}

	if _, err := s.acmeClient.Revoke(ctx, req); err != nil {
		return fmt.Errorf("revoke gagal: %w", err)
	}

	cert.Status = domain.CertStatusRevoked
	_ = s.certRepo.Update(ctx, cert)

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionCertRevoked,
		ResourceType: "certificate",
		Detail:       fmt.Sprintf("Certificate %s direvoke", cert.Name),
	})

	return nil
}

func (s *certificateService) Deploy(ctx context.Context, id string, req *domain.DeployCertRequest, actorID int) ([]*domain.CertJob, error) {
	if _, err := s.certRepo.FindByUUID(ctx, id); err != nil {
		return nil, err
	}
	// Deploy dilakukan oleh DistributionService — method ini hanya trigger
	// Kembalikan empty list, distribusi ditangani di handler
	return []*domain.CertJob{}, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func validateCreateCertRequest(req *domain.CreateCertRequest) error {
	if req.Name == "" {
		return errors.New("name wajib diisi")
	}
	if len(req.Domains) == 0 {
		return errors.New("domains wajib diisi minimal satu domain")
	}
	for _, d := range req.Domains {
		if !isValidCertDomain(d) {
			return fmt.Errorf("domain tidak valid: %s", d)
		}
	}
	if req.Provider == domain.CertProviderLetsEncrypt {
		if req.Challenge != domain.CertChallengeDNS01 && req.Challenge != domain.CertChallengeHTTP01 {
			return errors.New("challenge harus dns01 atau http01 untuk Let's Encrypt")
		}
		// Wildcard hanya boleh dengan DNS-01
		for _, d := range req.Domains {
			if strings.HasPrefix(d, "*.") && req.Challenge != domain.CertChallengeDNS01 {
				return errors.New("wildcard certificate hanya mendukung challenge dns01")
			}
		}
	}
	return nil
}

func extractPrimaryDomain(certPEM string) string {
	domains := extractAllDomains(certPEM)
	if len(domains) > 0 {
		return domains[0]
	}
	return ""
}

func extractAllDomains(certPEM string) []string {
	return []string{} // Parsing SAN domain dilakukan oleh storage.parseCertInfo di cert_store
}

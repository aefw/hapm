package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
	"github.com/aefw/hapm/pkg/storage"
)

// CMCHandler menangani semua endpoint Certificate Management Center
type CMCHandler struct {
	certSvc    domain.CertificateService
	jobSvc     domain.CertJobService
	distSvc    domain.DistributionService
	deployRepo domain.CertDeploymentRepository
	certStore  *storage.CertStore
	cfg        *config.Config
}

var reUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RegisterCMCRoutes mendaftarkan semua route CMC ke router.
// Prefix /api/v1/ssl/ dipertahankan untuk kompatibilitas.
func RegisterCMCRoutes(
	router *core.Router,
	cfg *config.Config,
	certSvc domain.CertificateService,
	jobSvc domain.CertJobService,
	distSvc domain.DistributionService,
	deployRepo domain.CertDeploymentRepository,
	certStore *storage.CertStore,
) {
	h := &CMCHandler{
		certSvc: certSvc, jobSvc: jobSvc, distSvc: distSvc,
		deployRepo: deployRepo, certStore: certStore, cfg: cfg,
	}

	// Providers
	router.GET("/api/v1/ssl/providers",
		middleware.RequireAuth(cfg, h.ListProviders))

	// Certificates CRUD
	router.GET("/api/v1/ssl/certificates",
		middleware.RequireAuth(cfg, h.List))
	router.POST("/api/v1/ssl/certificates",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Create)))
	router.GET("/api/v1/ssl/certificates/{uuid}",
		middleware.RequireAuth(cfg, h.GetByUUID))
	router.PUT("/api/v1/ssl/certificates/{uuid}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Update)))
	router.DELETE("/api/v1/ssl/certificates/{uuid}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Delete)))

	// Certificate actions
	router.POST("/api/v1/ssl/certificates/{uuid}/issue",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Issue)))
	router.POST("/api/v1/ssl/certificates/{uuid}/renew",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Renew)))
	router.POST("/api/v1/ssl/certificates/{uuid}/deploy",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Deploy)))
	router.POST("/api/v1/ssl/certificates/{uuid}/revoke",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Revoke)))
	router.GET("/api/v1/ssl/certificates/{uuid}/deployments",
		middleware.RequireAuth(cfg, h.ListDeployments))

	// Download file (requires auth) — semua 4 file tersedia
	router.GET("/api/v1/ssl/certificates/{uuid}/download/{file}",
		middleware.RequireAuth(cfg, h.Download))

	// Download public (tanpa auth) — hanya certificate.pem & chain.pem untuk MikroTik/scheduler
	router.GET("/api/v1/ssl/public/{uuid}/{file}",
		h.DownloadPublic)

	// Manual upload
	router.POST("/api/v1/ssl/upload",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Upload)))

	// Jobs & Logs
	router.GET("/api/v1/ssl/jobs",
		middleware.RequireAuth(cfg, h.ListJobs))
	router.GET("/api/v1/ssl/jobs/{uuid}",
		middleware.RequireAuth(cfg, h.GetJob))
	router.GET("/api/v1/ssl/certificates/{uuid}/jobs",
		middleware.RequireAuth(cfg, h.ListCertJobs))

	// HTTP-01 ACME challenge (public, tanpa auth)
	router.GET("/.well-known/acme-challenge/{token}",
		h.ServeChallenge)
}

// ListProviders godoc
// GET /api/v1/ssl/providers
func (h *CMCHandler) ListProviders(w http.ResponseWriter, r *http.Request, _ []string) {
	providers := []map[string]string{
		{"id": "letsencrypt", "name": "Let's Encrypt", "type": "acme"},
		{"id": "manual", "name": "Manual Upload", "type": "manual"},
	}
	core.Success(w, "Daftar provider certificate", providers)
}

// List godoc
// GET /api/v1/ssl/certificates
func (h *CMCHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	f := parseListFilter(r)
	certs, total, err := h.certSvc.List(r.Context(), f)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	respondList(w, "Daftar certificate", certs, total, f)
}

// GetByUUID godoc
// GET /api/v1/ssl/certificates/{uuid}
func (h *CMCHandler) GetByUUID(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	if uuid == "" {
		core.BadRequest(w, "UUID certificate tidak valid")
		return
	}
	cert, err := h.certSvc.GetByUUID(r.Context(), uuid)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Data certificate", cert)
}

// Create godoc
// POST /api/v1/ssl/certificates
func (h *CMCHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.CreateCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	cert, err := h.certSvc.Create(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Certificate berhasil dibuat", cert)
}

// Update godoc
// PUT /api/v1/ssl/certificates/{uuid}
func (h *CMCHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	var req domain.CreateCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	cert, err := h.certSvc.Update(r.Context(), uuid, &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Certificate berhasil diperbarui", cert)
}

// Delete godoc
// DELETE /api/v1/ssl/certificates/{uuid}
func (h *CMCHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	actorID := core.GetUserID(r.Context())
	if err := h.certSvc.Delete(r.Context(), uuid, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Certificate berhasil dihapus", nil)
}

// Issue godoc
// POST /api/v1/ssl/certificates/{uuid}/issue
func (h *CMCHandler) Issue(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	actorID := core.GetUserID(r.Context())
	job, err := h.certSvc.Issue(r.Context(), uuid, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Proses penerbitan certificate dimulai", job)
}

// Renew godoc
// POST /api/v1/ssl/certificates/{uuid}/renew
func (h *CMCHandler) Renew(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	actorID := core.GetUserID(r.Context())
	job, err := h.certSvc.Renew(r.Context(), uuid, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Proses renewal certificate dimulai", job)
}

// Deploy godoc
// POST /api/v1/ssl/certificates/{uuid}/deploy
func (h *CMCHandler) Deploy(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	var req domain.DeployCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())

	var deployments interface{}
	var err error

	if len(req.NodeIDs) == 0 {
		// Deploy ke semua node jika tidak ada node yang dipilih
		deployments, err = h.distSvc.DistributeToAll(r.Context(), uuid, actorID)
	} else {
		deployments, err = h.distSvc.Distribute(r.Context(), uuid, req.NodeIDs, actorID)
	}

	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Proses deployment certificate dimulai", deployments)
}

// Revoke godoc
// POST /api/v1/ssl/certificates/{uuid}/revoke
func (h *CMCHandler) Revoke(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	actorID := core.GetUserID(r.Context())
	if err := h.certSvc.Revoke(r.Context(), uuid, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Certificate berhasil direvoke", nil)
}

// ListDeployments godoc
// GET /api/v1/ssl/certificates/{uuid}/deployments
func (h *CMCHandler) ListDeployments(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	deployments, err := h.deployRepo.ListByCert(r.Context(), uuid)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	if deployments == nil {
		deployments = []*domain.CertDeployment{}
	}
	core.SuccessList(w, "Daftar deployment certificate", deployments)
}

// Upload godoc
// POST /api/v1/ssl/upload
func (h *CMCHandler) Upload(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.UploadCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	cert, err := h.certSvc.Upload(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Certificate berhasil diupload", cert)
}

// ListJobs godoc
// GET /api/v1/ssl/jobs
func (h *CMCHandler) ListJobs(w http.ResponseWriter, r *http.Request, _ []string) {
	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
			if limit > 200 {
				limit = 200
			}
		}
	}
	jobs, err := h.jobSvc.ListAll(r.Context(), limit)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	if jobs == nil {
		jobs = []*domain.CertJob{}
	}
	core.SuccessList(w, "Daftar jobs certificate", jobs)
}

// GetJob godoc
// GET /api/v1/ssl/jobs/{uuid}
func (h *CMCHandler) GetJob(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	job, err := h.jobSvc.GetByUUID(r.Context(), uuid)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Data job", job)
}

// ListCertJobs godoc
// GET /api/v1/ssl/certificates/{uuid}/jobs
func (h *CMCHandler) ListCertJobs(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	jobs, err := h.jobSvc.ListByCert(r.Context(), uuid, 20)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	if jobs == nil {
		jobs = []*domain.CertJob{}
	}
	core.SuccessList(w, "Daftar jobs certificate", jobs)
}

// Download melayani download file certificate (memerlukan autentikasi).
// GET /api/v1/ssl/certificates/{uuid}/download/{file}
// File yang tersedia: certificate.pem, chain.pem, issuer.pem, private.key
func (h *CMCHandler) Download(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	filename := params[1]

	if !reUUID.MatchString(uuid) {
		core.NotFound(w, "Certificate tidak ditemukan")
		return
	}

	allowed := map[string]bool{
		"certificate.pem": true,
		"chain.pem":       true,
		"issuer.pem":      true,
		"private.key":     true,
	}
	if !allowed[filename] {
		core.NotFound(w, "File tidak ditemukan")
		return
	}

	cert, err := h.certSvc.GetByUUID(r.Context(), uuid)
	if err != nil {
		core.NotFound(w, "Certificate tidak ditemukan")
		return
	}

	h.serveFile(w, r, uuid, filename, cert.Name)
}

// DownloadPublic melayani download file certificate tanpa autentikasi.
// GET /api/v1/ssl/public/{uuid}/{file}
// Hanya certificate.pem dan chain.pem yang boleh diakses publik (untuk MikroTik/scheduler).
func (h *CMCHandler) DownloadPublic(w http.ResponseWriter, r *http.Request, params []string) {
	uuid := params[0]
	filename := params[1]

	if !reUUID.MatchString(uuid) {
		http.NotFound(w, r)
		return
	}

	// Hanya 2 file publik yang diizinkan
	if filename != "certificate.pem" && filename != "chain.pem" {
		http.NotFound(w, r)
		return
	}

	h.serveFile(w, r, uuid, filename, "")
}

// serveFile membaca dan mengirim file certificate sebagai attachment download.
func (h *CMCHandler) serveFile(w http.ResponseWriter, r *http.Request, uuid, filename, certName string) {
	paths := h.certStore.Paths(uuid)

	var filePath string
	switch filename {
	case "certificate.pem":
		filePath = paths.CertPEM
	case "chain.pem":
		filePath = paths.ChainPEM
	case "issuer.pem":
		filePath = paths.IssuerPEM
	case "private.key":
		filePath = paths.KeyPEM
	default:
		http.NotFound(w, r)
		return
	}

	if _, err := os.Stat(filePath); err != nil {
		core.NotFound(w, "File belum tersedia")
		return
	}

	// Nama file download: {nama-cert}_{filename} atau langsung filename jika tanpa nama
	downloadName := filename
	if certName != "" {
		safe := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-").Replace(certName)
		downloadName = fmt.Sprintf("%s_%s", safe, filename)
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, downloadName))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, filePath)
}

// ServeChallenge melayani HTTP-01 ACME challenge files.
// GET /.well-known/acme-challenge/{token}
// File dibaca dari CMC webroot yang diisi oleh hapm-acme (LEGO webroot mode).
func (h *CMCHandler) ServeChallenge(w http.ResponseWriter, r *http.Request, params []string) {
	token := params[0]
	if token == "" {
		http.NotFound(w, r)
		return
	}

	webRootPath := h.cfg.CMC.WebRootPath
	http.ServeFile(w, r, webRootPath+"/.well-known/acme-challenge/"+token)
}

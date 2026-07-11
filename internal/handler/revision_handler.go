package handler

import (
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// RevisionHandler menangani semua endpoint manajemen revisi konfigurasi.
type RevisionHandler struct {
	svc domain.RevisionService
	cfg *config.Config
}

// RegisterRevisionRoutes mendaftarkan semua route revision ke router.
func RegisterRevisionRoutes(router *core.Router, cfg *config.Config, svc domain.RevisionService) {
	h := &RevisionHandler{svc: svc, cfg: cfg}

	// Daftar revisi per node
	router.GET("/api/v1/nodes/{id}/revisions",
		middleware.RequireAuth(cfg, h.ListByNode))

	// Detail revisi tertentu (by revision number)
	router.GET("/api/v1/nodes/{id}/revisions/{rev}",
		middleware.RequireAuth(cfg, h.GetRevision))

	// Diff antara revisi dengan revisi sebelumnya
	router.GET("/api/v1/nodes/{id}/revisions/{rev}/diff",
		middleware.RequireAuth(cfg, h.Diff))

	// Restore ke revisi tertentu (membuat deployment baru)
	router.POST("/api/v1/nodes/{id}/revisions/{rev}/restore",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Restore)))
}

// ListByNode godoc
// GET /api/v1/nodes/{id}/revisions   [Auth Required]
func (h *RevisionHandler) ListByNode(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	revisions, err := h.svc.ListByNode(r.Context(), nodeID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.SuccessList(w, "Daftar revisi konfigurasi", revisions)
}

// GetRevision godoc
// GET /api/v1/nodes/{id}/revisions/{rev}   [Auth Required]
func (h *RevisionHandler) GetRevision(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}
	revNum, ok := parseID(params, 1)
	if !ok {
		core.BadRequest(w, "Nomor revisi tidak valid")
		return
	}

	revision, err := h.svc.GetRevision(r.Context(), nodeID, revNum)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Detail revisi konfigurasi", revision)
}

// Diff godoc
// GET /api/v1/nodes/{id}/revisions/{rev}/diff   [Auth Required]
// Mengembalikan unified diff antara revisi ini dan revisi sebelumnya.
func (h *RevisionHandler) Diff(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}
	revNum, ok := parseID(params, 1)
	if !ok {
		core.BadRequest(w, "Nomor revisi tidak valid")
		return
	}

	diff, err := h.svc.Diff(r.Context(), nodeID, revNum)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Diff revisi konfigurasi", diff)
}

// Restore godoc
// POST /api/v1/nodes/{id}/revisions/{rev}/restore   [Admin+]
// Membuat deployment baru yang me-restore konfigurasi dari revisi tertentu.
func (h *RevisionHandler) Restore(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}
	revNum, ok := parseID(params, 1)
	if !ok {
		core.BadRequest(w, "Nomor revisi tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	if err := h.svc.Restore(r.Context(), nodeID, revNum, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Restore konfigurasi berhasil dimulai", nil)
}

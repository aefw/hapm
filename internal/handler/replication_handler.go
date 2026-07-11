package handler

import (
	"encoding/json"
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// ReplicationHandler menangani semua endpoint replication antar node.
type ReplicationHandler struct {
	svc domain.ReplicationService
	cfg *config.Config
}

// RegisterReplicationRoutes mendaftarkan semua route replication ke router.
func RegisterReplicationRoutes(router *core.Router, cfg *config.Config, svc domain.ReplicationService) {
	h := &ReplicationHandler{svc: svc, cfg: cfg}

	// Replication targets CRUD
	router.GET("/api/v1/replication/targets",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.ListTargets)))
	router.POST("/api/v1/replication/targets",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.CreateTarget)))
	router.PUT("/api/v1/replication/targets/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.UpdateTarget)))
	router.DELETE("/api/v1/replication/targets/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.DeleteTarget)))

	// Push replication ke target tertentu
	router.POST("/api/v1/replication/targets/{id}/push",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Push)))

	// Drift detection — cek semua node
	router.GET("/api/v1/replication/drift",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.CheckDrift)))
}

// ListTargets godoc
// GET /api/v1/replication/targets   [Admin+]
func (h *ReplicationHandler) ListTargets(w http.ResponseWriter, r *http.Request, _ []string) {
	targets, err := h.svc.ListTargets(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.SuccessList(w, "Daftar replication target", targets)
}

// CreateTarget godoc
// POST /api/v1/replication/targets   [Admin+]
// Body: {"id_nodes_source":1,"id_nodes_target":2,"sync_frontends":true,"sync_backends":true,"sync_ssl":true,"enabled":true}
func (h *ReplicationHandler) CreateTarget(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.CreateReplicationTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	if req.SourceNodeID == 0 || req.TargetNodeID == 0 {
		core.BadRequest(w, "id_nodes_source dan id_nodes_target wajib diisi")
		return
	}

	actorID := core.GetUserID(r.Context())
	target, err := h.svc.CreateTarget(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Replication target berhasil dibuat", target)
}

// UpdateTarget godoc
// PUT /api/v1/replication/targets/{id}   [Admin+]
func (h *ReplicationHandler) UpdateTarget(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID replication target tidak valid")
		return
	}

	var req domain.CreateReplicationTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	target, err := h.svc.UpdateTarget(r.Context(), id, &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Replication target berhasil diupdate", target)
}

// DeleteTarget godoc
// DELETE /api/v1/replication/targets/{id}   [Admin+]
func (h *ReplicationHandler) DeleteTarget(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID replication target tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	if err := h.svc.DeleteTarget(r.Context(), id, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Replication target berhasil dihapus", nil)
}

// Push godoc
// POST /api/v1/replication/targets/{id}/push   [Admin+]
// Memulai proses replikasi konfigurasi dari source ke target node.
// Berjalan async — respons langsung dengan ReplicationJob record.
func (h *ReplicationHandler) Push(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID replication target tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	job, err := h.svc.PushReplication(r.Context(), id, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Replikasi berhasil dimulai", job)
}

// CheckDrift godoc
// GET /api/v1/replication/drift   [Admin+]
// Membandingkan konfigurasi aktual di semua node dengan konfigurasi yang seharusnya.
func (h *ReplicationHandler) CheckDrift(w http.ResponseWriter, r *http.Request, _ []string) {
	reports, err := h.svc.CheckDrift(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.SuccessList(w, "Hasil drift detection", reports)
}

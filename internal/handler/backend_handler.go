package handler

import (
	"encoding/json"
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// BackendHandler menangani semua endpoint manajemen backend pool dan server.
type BackendHandler struct {
	svc domain.BackendService
	cfg *config.Config
}

// RegisterBackendRoutes mendaftarkan semua route backend ke router.
func RegisterBackendRoutes(router *core.Router, cfg *config.Config, svc domain.BackendService) {
	h := &BackendHandler{svc: svc, cfg: cfg}

	// Pool CRUD
	router.GET("/api/v1/backends",
		middleware.RequireAuth(cfg, h.ListPools))
	router.POST("/api/v1/backends",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.CreatePool)))
	router.GET("/api/v1/backends/{id}",
		middleware.RequireAuth(cfg, h.GetPool))
	router.PUT("/api/v1/backends/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.UpdatePool)))
	router.DELETE("/api/v1/backends/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.DeletePool)))

}

// ListPools godoc
// GET /api/v1/backends   [Auth Required]
// Query: q=keyword (name/description), start=0, limit=50
func (h *BackendHandler) ListPools(w http.ResponseWriter, r *http.Request, _ []string) {
	f := parseListFilter(r)
	pools, total, err := h.svc.ListPools(r.Context(), f)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	respondList(w, "Daftar backend pool", pools, total, f)
}

// GetPool godoc
// GET /api/v1/backends/{id}   [Auth Required]
func (h *BackendHandler) GetPool(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID backend pool tidak valid")
		return
	}

	pool, err := h.svc.GetPoolByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Data backend pool", pool)
}

// CreatePool godoc
// POST /api/v1/backends   [Admin+]
// Body: {"name":"...","algorithm":"roundrobin","timeout_connect":5000,"timeout_server":30000,"health_check":true}
func (h *BackendHandler) CreatePool(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.CreatePoolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	if req.Name == "" {
		core.BadRequest(w, "name wajib diisi")
		return
	}

	actorID := core.GetUserID(r.Context())
	pool, err := h.svc.CreatePool(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Backend pool berhasil dibuat", pool)
}

// UpdatePool godoc
// PUT /api/v1/backends/{id}   [Admin+]
func (h *BackendHandler) UpdatePool(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID backend pool tidak valid")
		return
	}

	var req domain.CreatePoolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	pool, err := h.svc.UpdatePool(r.Context(), id, &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Backend pool berhasil diupdate", pool)
}

// DeletePool godoc
// DELETE /api/v1/backends/{id}   [Admin+]
func (h *BackendHandler) DeletePool(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID backend pool tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	if err := h.svc.DeletePool(r.Context(), id, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Backend pool berhasil dihapus", nil)
}


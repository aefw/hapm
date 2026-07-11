package handler

import (
	"encoding/json"
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// ServiceHandler menangani semua endpoint manajemen service HAProxy (TCP/HTTP port balancing).
type ServiceHandler struct {
	svc domain.ServiceService
	cfg *config.Config
}

// RegisterServiceRoutes mendaftarkan semua route service ke router.
func RegisterServiceRoutes(router *core.Router, cfg *config.Config, svc domain.ServiceService) {
	h := &ServiceHandler{svc: svc, cfg: cfg}

	router.GET("/api/v1/services",
		middleware.RequireAuth(cfg, h.List))
	router.POST("/api/v1/services",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Create)))
	router.GET("/api/v1/services/{id}",
		middleware.RequireAuth(cfg, h.GetByID))
	router.PUT("/api/v1/services/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Update)))
	router.DELETE("/api/v1/services/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Delete)))
}

// List godoc
// GET /api/v1/services   [Auth Required]
// Query: q=keyword (name/description), start=0, limit=50
func (h *ServiceHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	f := parseListFilter(r)
	services, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	respondList(w, "Daftar service", services, total, f)
}

// GetByID godoc
// GET /api/v1/services/{id}   [Auth Required]
func (h *ServiceHandler) GetByID(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID service tidak valid")
		return
	}

	svc, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Data service", svc)
}

// Create godoc
// POST /api/v1/services   [Admin+]
// Body: {"name":"ssh_cluster","service_type":"TCP","listen_port":22,"id_backend_pools":1,"enabled":true}
func (h *ServiceHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.CreateServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	svc, err := h.svc.Create(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Service berhasil ditambahkan", svc)
}

// Update godoc
// PUT /api/v1/services/{id}   [Admin+]
func (h *ServiceHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID service tidak valid")
		return
	}

	var req domain.CreateServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	svc, err := h.svc.Update(r.Context(), id, &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Service berhasil diupdate", svc)
}

// Delete godoc
// DELETE /api/v1/services/{id}   [Admin+]
func (h *ServiceHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID service tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	if err := h.svc.Delete(r.Context(), id, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Service berhasil dihapus", nil)
}

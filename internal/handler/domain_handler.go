package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// DomainHandler menangani semua endpoint manajemen domain routing.
type DomainHandler struct {
	svc domain.DomainService
	cfg *config.Config
}

// RegisterDomainRoutes mendaftarkan semua route domain ke router.
func RegisterDomainRoutes(router *core.Router, cfg *config.Config, svc domain.DomainService) {
	h := &DomainHandler{svc: svc, cfg: cfg}

	router.GET("/api/v1/domains",
		middleware.RequireAuth(cfg, h.List))
	router.POST("/api/v1/domains",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Create)))
	router.GET("/api/v1/domains/{id}",
		middleware.RequireAuth(cfg, h.GetByID))
	router.PUT("/api/v1/domains/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Update)))
	router.DELETE("/api/v1/domains/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Delete)))
}

// List godoc
// GET /api/v1/domains   [Auth Required]
// Query: q=keyword (domain_name/description), start=0, limit=50, id_auth_groups=N
func (h *DomainHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	f := parseListFilter(r)
	if s := r.URL.Query().Get("id_auth_groups"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			f.AuthGroupID = &v
		}
	}
	domains, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	respondList(w, "Daftar domain", domains, total, f)
}

// GetByID godoc
// GET /api/v1/domains/{id}   [Auth Required]
func (h *DomainHandler) GetByID(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID domain tidak valid")
		return
	}

	d, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Data domain", d)
}

// Create godoc
// POST /api/v1/domains   [Admin+]
// Body: {"domain_name":"example.com","id_backend_pools":1,"ssl_mode":"none","http_redirect":false,"enabled":true}
func (h *DomainHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.CreateDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	if req.DomainName == "" {
		core.BadRequest(w, "domain_name wajib diisi")
		return
	}

	actorID := core.GetUserID(r.Context())
	d, err := h.svc.Create(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Domain berhasil ditambahkan", d)
}

// Update godoc
// PUT /api/v1/domains/{id}   [Admin+]
func (h *DomainHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID domain tidak valid")
		return
	}

	var req domain.CreateDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	d, err := h.svc.Update(r.Context(), id, &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Domain berhasil diupdate", d)
}

// Delete godoc
// DELETE /api/v1/domains/{id}   [Admin+]
func (h *DomainHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID domain tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	if err := h.svc.Delete(r.Context(), id, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Domain berhasil dihapus", nil)
}

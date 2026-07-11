package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// NodeHandler menangani semua endpoint manajemen node HAProxy.
type NodeHandler struct {
	svc domain.NodeService
	cfg *config.Config
}

// RegisterNodeRoutes mendaftarkan semua route node ke router.
// Semua route memerlukan autentikasi Admin+.
func RegisterNodeRoutes(router *core.Router, cfg *config.Config, svc domain.NodeService) {
	h := &NodeHandler{svc: svc, cfg: cfg}

	router.GET("/api/v1/nodes",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.List)))
	router.POST("/api/v1/nodes",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Create)))
	router.GET("/api/v1/nodes/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.GetByID)))
	router.PUT("/api/v1/nodes/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Update)))
	router.DELETE("/api/v1/nodes/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.Delete)))

	// Aksi khusus node
	router.POST("/api/v1/nodes/{id}/test",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.TestConnection)))
	router.POST("/api/v1/nodes/{id}/provision",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.Provision)))
}

// List godoc
// GET /api/v1/nodes   [Admin+]
// Query: q=keyword (name/hostname/ip/description), start=0, limit=50
func (h *NodeHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	f := parseListFilter(r)
	nodes, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	respondList(w, "Daftar node", nodes, total, f)
}

// GetByID godoc
// GET /api/v1/nodes/{id}   [Admin+]
func (h *NodeHandler) GetByID(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	node, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Data node", node)
}

// Create godoc
// POST /api/v1/nodes   [Admin+]
// Body: {"name":"...","hostname":"...","ip_address":"...","ssh_port":22,"ssh_user":"root","ssh_private_key":"..."}
func (h *NodeHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.CreateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	if req.Name == "" || req.IPAddress == "" || req.SSHUser == "" {
		core.BadRequest(w, "name, ip_address, dan ssh_user wajib diisi")
		return
	}

	actorID := core.GetUserID(r.Context())
	node, err := h.svc.Create(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Node berhasil ditambahkan", node)
}

// Update godoc
// PUT /api/v1/nodes/{id}   [Admin+]
func (h *NodeHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	var req domain.UpdateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	node, err := h.svc.Update(r.Context(), id, &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Node berhasil diupdate", node)
}

// Delete godoc
// DELETE /api/v1/nodes/{id}   [SuperAdmin]
func (h *NodeHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	if err := h.svc.Delete(r.Context(), id, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Node berhasil dihapus", nil)
}

// TestConnection godoc
// POST /api/v1/nodes/{id}/test   [Admin+]
// Menguji koneksi SSH ke node dan melaporkan HAProxy version + latency.
func (h *NodeHandler) TestConnection(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	result, err := h.svc.TestConnection(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Hasil test koneksi", result)
}

// Provision godoc
// POST /api/v1/nodes/{id}/provision   [SuperAdmin]
// Menginstall dan mengkonfigurasi HAProxy di node via SSH.
// Dijalankan secara async karena proses install paket bisa memakan beberapa menit.
// Response 202 Accepted dikembalikan segera; pantau status node via GET /nodes/{id}.
func (h *NodeHandler) Provision(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())

	// Jalankan provision di background — install paket bisa 2-5 menit,
	// jauh melebihi WriteTimeout server (30s). Context baru agar tidak
	// dibatalkan saat HTTP request selesai.
	go func() {
		_ = h.svc.Provision(context.Background(), id, actorID)
	}()

	core.Error(w, http.StatusAccepted, "Provisioning dimulai — install HAProxy sedang berjalan di background. Pantau status node via GET /api/v1/nodes/"+strconv.Itoa(id))
}

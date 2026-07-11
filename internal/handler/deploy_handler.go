package handler

import (
	"encoding/json"
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// DeployHandler menangani semua endpoint deployment HAProxy.
type DeployHandler struct {
	svc domain.DeployService
	cfg *config.Config
}

// RegisterDeployRoutes mendaftarkan semua route deploy ke router.
func RegisterDeployRoutes(router *core.Router, cfg *config.Config, svc domain.DeployService) {
	h := &DeployHandler{svc: svc, cfg: cfg}

	// Memulai deployment baru ke node
	router.POST("/api/v1/nodes/{id}/deploy",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Deploy)))

	// Status deployment tertentu
	router.GET("/api/v1/deployments/{id}",
		middleware.RequireAuth(cfg, h.GetStatus))

	// Riwayat deployment per node
	router.GET("/api/v1/nodes/{id}/deployments",
		middleware.RequireAuth(cfg, h.ListByNode))
}

// Deploy godoc
// POST /api/v1/nodes/{id}/deploy   [Admin+]
// Body: {"comment":"Deploy hotfix v1.2"}
// Respons langsung dengan Deployment record (status=pending/running).
// Pipeline berjalan async di background goroutine.
func (h *DeployHandler) Deploy(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	// Ambil comment opsional dari body
	var body struct {
		Comment string `json:"comment"`
	}
	// Ignore decode error — comment is optional
	_ = json.NewDecoder(r.Body).Decode(&body)

	actorID := core.GetUserID(r.Context())
	req := &domain.DeployRequest{
		NodeID:  nodeID,
		Comment: body.Comment,
		UserID:  actorID,
	}

	deployment, err := h.svc.Deploy(r.Context(), req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	core.Created(w, "Deployment berhasil dimulai", deployment)
}

// GetStatus godoc
// GET /api/v1/deployments/{id}   [Auth Required]
// Mendapatkan status deployment berdasarkan ID.
func (h *DeployHandler) GetStatus(w http.ResponseWriter, r *http.Request, params []string) {
	deployID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID deployment tidak valid")
		return
	}

	deployment, err := h.svc.GetStatus(r.Context(), deployID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	core.Success(w, "Status deployment", deployment)
}

// ListByNode godoc
// GET /api/v1/nodes/{id}/deployments?limit=20   [Auth Required]
// Mendapatkan riwayat deployment untuk node tertentu.
func (h *DeployHandler) ListByNode(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	// Parse query param limit (default 10, max 100)
	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, ok := parseID([]string{l}, 0); ok {
			limit = parsed
			if limit > 100 {
				limit = 100
			}
		}
	}

	deployments, err := h.svc.ListByNode(r.Context(), nodeID, limit)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	core.SuccessList(w, "Riwayat deployment", deployments)
}

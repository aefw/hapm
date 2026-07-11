package handler

import (
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// ConfigHandler menangani semua endpoint generate & validasi konfigurasi HAProxy.
type ConfigHandler struct {
	svc domain.ConfigService
	cfg *config.Config
}

// RegisterConfigRoutes mendaftarkan semua route config ke router.
func RegisterConfigRoutes(router *core.Router, cfg *config.Config, svc domain.ConfigService) {
	h := &ConfigHandler{svc: svc, cfg: cfg}

	// Generate konfigurasi untuk node tertentu
	router.GET("/api/v1/nodes/{id}/config",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.GenerateForNode)))

	// Validasi konfigurasi yang akan diterapkan
	router.POST("/api/v1/nodes/{id}/config/validate",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.ValidateConfig)))
}

// GenerateForNode godoc
// GET /api/v1/nodes/{id}/config   [Admin+]
// Menghasilkan konfigurasi HAProxy untuk node berdasarkan domain & backend saat ini.
// Tidak menyimpan atau men-deploy — hanya preview/generate.
func (h *ConfigHandler) GenerateForNode(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	cfg, err := h.svc.GenerateForNode(r.Context(), nodeID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Konfigurasi HAProxy berhasil digenerate", cfg)
}

// ValidateConfig godoc
// POST /api/v1/nodes/{id}/config/validate   [Admin+]
// Memvalidasi konfigurasi yang akan diterapkan ke node tanpa benar-benar deploy.
// Menjalankan `haproxy -c -f` di node via SSH.
func (h *ConfigHandler) ValidateConfig(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	valid, msg, err := h.svc.ValidateConfig(r.Context(), nodeID)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	type validateResult struct {
		Valid   bool   `json:"valid"`
		Message string `json:"message"`
	}

	if valid {
		core.Success(w, "Konfigurasi valid", &validateResult{Valid: true, Message: msg})
	} else {
		core.Success(w, "Konfigurasi tidak valid", &validateResult{Valid: false, Message: msg})
	}
}

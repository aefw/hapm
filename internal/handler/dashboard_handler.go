package handler

import (
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// DashboardHandler menangani semua endpoint dashboard.
type DashboardHandler struct {
	svc domain.DashboardService
	cfg *config.Config
}

// RegisterDashboardRoutes mendaftarkan semua route dashboard ke router.
func RegisterDashboardRoutes(router *core.Router, cfg *config.Config, svc domain.DashboardService) {
	h := &DashboardHandler{svc: svc, cfg: cfg}

	// Overview: data DB saja, response cepat
	router.GET("/api/v1/dashboard",
		middleware.RequireAuth(cfg, h.GetOverview))

	// Live stats: SSH ke semua node secara paralel, bisa lambat
	router.GET("/api/v1/dashboard/nodes/stats",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.GetAllNodeStats)))
}

// GetOverview godoc
// GET /api/v1/dashboard   [Auth Required]
// Ringkasan sistem dari DB: jumlah node/domain/backend/service/ssl,
// status tiap node, deployment terakhir per node, 10 deployment terbaru,
// dan 10 audit log terbaru.
func (h *DashboardHandler) GetOverview(w http.ResponseWriter, r *http.Request, params []string) {
	data, err := h.svc.GetOverview(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Dashboard overview", data)
}

// GetAllNodeStats godoc
// GET /api/v1/dashboard/nodes/stats   [Admin Required]
// Mengambil live HAProxy stats dari semua node secara paralel via SSH.
// Tiap node punya timeout 15 detik; node yang gagal tetap muncul
// dengan field "error" diisi, bukan menggagalkan seluruh request.
func (h *DashboardHandler) GetAllNodeStats(w http.ResponseWriter, r *http.Request, params []string) {
	stats, err := h.svc.GetAllNodeStats(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.SuccessList(w, "Live stats semua node", stats)
}

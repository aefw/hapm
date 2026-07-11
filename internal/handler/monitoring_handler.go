package handler

import (
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// MonitoringHandler menangani semua endpoint monitoring HAProxy stats.
type MonitoringHandler struct {
	svc domain.MonitoringService
	cfg *config.Config
}

// RegisterMonitoringRoutes mendaftarkan semua route monitoring ke router.
func RegisterMonitoringRoutes(router *core.Router, cfg *config.Config, svc domain.MonitoringService) {
	h := &MonitoringHandler{svc: svc, cfg: cfg}

	// Stats lengkap untuk node (frontend + backend gabungan)
	router.GET("/api/v1/nodes/{id}/stats",
		middleware.RequireAuth(cfg, h.GetNodeStats))

	// Stats frontend saja
	router.GET("/api/v1/nodes/{id}/stats/frontends",
		middleware.RequireAuth(cfg, h.GetFrontendStats))

	// Stats backend saja
	router.GET("/api/v1/nodes/{id}/stats/backends",
		middleware.RequireAuth(cfg, h.GetBackendStats))
}

// GetNodeStats godoc
// GET /api/v1/nodes/{id}/stats   [Auth Required]
// Mendapatkan semua statistik HAProxy untuk node (frontend + backend + server).
func (h *MonitoringHandler) GetNodeStats(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	stats, err := h.svc.GetNodeStats(r.Context(), nodeID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Statistik HAProxy node", stats)
}

// GetFrontendStats godoc
// GET /api/v1/nodes/{id}/stats/frontends   [Auth Required]
func (h *MonitoringHandler) GetFrontendStats(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	stats, err := h.svc.GetFrontendStats(r.Context(), nodeID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.SuccessList(w, "Statistik frontend HAProxy", stats)
}

// GetBackendStats godoc
// GET /api/v1/nodes/{id}/stats/backends   [Auth Required]
func (h *MonitoringHandler) GetBackendStats(w http.ResponseWriter, r *http.Request, params []string) {
	nodeID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID node tidak valid")
		return
	}

	stats, err := h.svc.GetBackendStats(r.Context(), nodeID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.SuccessList(w, "Statistik backend HAProxy", stats)
}

package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

type licHandler struct {
	cfg *config.Config
	svc domain.SNService
}

func RegisterLicRoutes(router *core.Router, cfg *config.Config, svc domain.SNService) {
	h := &licHandler{cfg: cfg, svc: svc}
	router.GET("/api/v1/sn", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Status)))
	router.POST("/api/v1/sn/activate", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.Activate)))
}

// GET /api/v1/sn — status file lokal tanpa mengunduh (Admin+)
func (h *licHandler) Status(w http.ResponseWriter, r *http.Request, _ []string) {
	result, err := h.svc.Status(r.Context())
	if err != nil {
		core.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	core.Success(w, "sn", result)
}

// POST /api/v1/sn/activate — unduh license menggunakan kode, aktifkan jika valid (SuperAdmin)
func (h *licHandler) Activate(w http.ResponseWriter, r *http.Request, _ []string) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Code) == "" {
		core.Error(w, http.StatusBadRequest, "kode aktivasi diperlukan")
		return
	}
	result, err := h.svc.Activate(r.Context(), strings.TrimSpace(body.Code))
	if err != nil {
		core.JSON(w, http.StatusUnprocessableEntity, false, err.Error(), result, nil)
		return
	}
	core.Success(w, "sn", result)
}

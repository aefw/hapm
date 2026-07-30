package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

type WAFWhitelistHandler struct {
	cfg         *config.Config
	repo        domain.WAFWhitelistRepository
	settingsSvc domain.SettingsService
}

func RegisterWAFWhitelistRoutes(
	router *core.Router,
	cfg *config.Config,
	repo domain.WAFWhitelistRepository,
	settingsSvc domain.SettingsService,
) {
	h := &WAFWhitelistHandler{cfg: cfg, repo: repo, settingsSvc: settingsSvc}
	router.GET("/api/v1/waf/whitelist", middleware.RequireAuth(cfg, h.List))
	router.POST("/api/v1/waf/whitelist", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.Create)))
	router.DELETE("/api/v1/waf/whitelist/{id}", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.Delete)))
}

// GET /api/v1/waf/whitelist
func (h *WAFWhitelistHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()
	featureEnabled, _ := h.settingsSvc.IsWAFEnabled(ctx)

	list, err := h.repo.List(ctx)
	if err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal mengambil whitelist: "+err.Error())
		return
	}
	if list == nil {
		list = []*domain.WAFWhitelist{}
	}
	core.Success(w, "whitelist", map[string]interface{}{
		"feature_enabled": featureEnabled,
		"entries":         list,
	})
}

type whitelistCreateRequest struct {
	IPAddress   string  `json:"ip_address"`
	Description string  `json:"description"`
	ExpiresAt   *string `json:"expires_at"`
	DomainIDs   []int   `json:"domain_ids"`
}

// POST /api/v1/waf/whitelist
func (h *WAFWhitelistHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()

	enabled, _ := h.settingsSvc.IsWAFEnabled(ctx)
	if !enabled {
		core.Error(w, http.StatusForbidden, "Fitur WAF tidak aktif.")
		return
	}

	var req whitelistCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}

	req.IPAddress = strings.TrimSpace(req.IPAddress)
	if req.IPAddress == "" {
		core.Error(w, http.StatusBadRequest, "IP address tidak boleh kosong")
		return
	}
	if !isValidIPOrCIDR(req.IPAddress) {
		core.Error(w, http.StatusBadRequest, "IP address atau CIDR tidak valid")
		return
	}

	wl := &domain.WAFWhitelist{
		IPAddress:   req.IPAddress,
		Description: strings.TrimSpace(req.Description),
		DomainIDs:   req.DomainIDs,
	}
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			core.Error(w, http.StatusBadRequest, "Format expires_at tidak valid (gunakan RFC3339)")
			return
		}
		wl.ExpiresAt = &t
	}

	if err := h.repo.Create(ctx, wl); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menyimpan whitelist entry: "+err.Error())
		return
	}
	core.Success(w, "whitelist", wl)
}

// DELETE /api/v1/waf/whitelist/{id}
func (h *WAFWhitelistHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	ctx := r.Context()

	enabled, _ := h.settingsSvc.IsWAFEnabled(ctx)
	if !enabled {
		core.Error(w, http.StatusForbidden, "Fitur WAF tidak aktif.")
		return
	}

	id, err := strconv.Atoi(params[0])
	if err != nil {
		core.Error(w, http.StatusBadRequest, "ID tidak valid")
		return
	}

	if _, err := h.repo.FindByID(ctx, id); err != nil {
		core.Error(w, http.StatusNotFound, "Whitelist entry tidak ditemukan")
		return
	}

	if err := h.repo.Delete(ctx, id); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menghapus whitelist entry: "+err.Error())
		return
	}
	core.Success(w, "message", "Whitelist entry berhasil dihapus")
}

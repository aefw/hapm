package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

type WAFBlacklistHandler struct {
	cfg         *config.Config
	repo        domain.WAFBlacklistRepository
	settingsSvc domain.SettingsService
}

func RegisterWAFBlacklistRoutes(
	router *core.Router,
	cfg *config.Config,
	repo domain.WAFBlacklistRepository,
	settingsSvc domain.SettingsService,
) {
	h := &WAFBlacklistHandler{cfg: cfg, repo: repo, settingsSvc: settingsSvc}
	router.GET("/api/v1/waf/blacklist", middleware.RequireAuth(cfg, h.List))
	router.POST("/api/v1/waf/blacklist", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Create)))
	router.DELETE("/api/v1/waf/blacklist/{id}", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Delete)))
}

// GET /api/v1/waf/blacklist
func (h *WAFBlacklistHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()
	featureEnabled, _ := h.settingsSvc.IsWAFEnabled(ctx)

	list, err := h.repo.List(ctx)
	if err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal mengambil blacklist: "+err.Error())
		return
	}
	if list == nil {
		list = []*domain.WAFBlacklist{}
	}
	core.Success(w, "blacklist", map[string]interface{}{
		"feature_enabled": featureEnabled,
		"entries":         list,
	})
}

type blacklistCreateRequest struct {
	IPAddress string  `json:"ip_address"`
	Reason    string  `json:"reason"`
	ExpiresAt *string `json:"expires_at"`
	DomainIDs []int   `json:"domain_ids"`
}

// POST /api/v1/waf/blacklist
func (h *WAFBlacklistHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()

	enabled, _ := h.settingsSvc.IsWAFEnabled(ctx)
	if !enabled {
		core.Error(w, http.StatusForbidden, "Fitur WAF tidak aktif.")
		return
	}

	var req blacklistCreateRequest
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

	bl := &domain.WAFBlacklist{
		IPAddress: req.IPAddress,
		Reason:    strings.TrimSpace(req.Reason),
		DomainIDs: req.DomainIDs,
	}
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			core.Error(w, http.StatusBadRequest, "Format expires_at tidak valid (gunakan RFC3339)")
			return
		}
		bl.ExpiresAt = &t
	}

	if err := h.repo.Create(ctx, bl); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menyimpan blacklist entry: "+err.Error())
		return
	}
	core.Success(w, "blacklist", bl)
}

// DELETE /api/v1/waf/blacklist/{id}
func (h *WAFBlacklistHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
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
		core.Error(w, http.StatusNotFound, "Blacklist entry tidak ditemukan")
		return
	}

	if err := h.repo.Delete(ctx, id); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menghapus blacklist entry: "+err.Error())
		return
	}
	core.Success(w, "message", "Blacklist entry berhasil dihapus")
}

func isValidIPOrCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}

package handler

import (
	"encoding/json"
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// SettingsHandler menangani endpoint konfigurasi global HAPM (termasuk Cloudflare)
type SettingsHandler struct {
	settingsSvc domain.SettingsService
	cfg         *config.Config
}

// RegisterSettingsRoutes mendaftarkan route settings ke router
func RegisterSettingsRoutes(router *core.Router, cfg *config.Config, settingsSvc domain.SettingsService) {
	h := &SettingsHandler{settingsSvc: settingsSvc, cfg: cfg}

	// Cloudflare settings
	router.PUT("/api/v1/settings/cloudflare",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.SetCloudflare)))
	router.POST("/api/v1/settings/cloudflare/test",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.TestCloudflare)))
	router.GET("/api/v1/settings/cloudflare/zones",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.DiscoverZones)))

	// ACME settings
	router.PUT("/api/v1/settings/acme",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.SetACME)))
	router.GET("/api/v1/settings/acme",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.GetACME)))
}

// SetCloudflare godoc
// PUT /api/v1/settings/cloudflare   [SuperAdmin]
// Body: {"api_token":"..."}
func (h *SettingsHandler) SetCloudflare(w http.ResponseWriter, r *http.Request, _ []string) {
	var req struct {
		APIToken string `json:"api_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	if req.APIToken == "" {
		core.BadRequest(w, "api_token wajib diisi")
		return
	}

	if err := h.settingsSvc.SetCloudflareToken(r.Context(), req.APIToken); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Cloudflare API Token berhasil disimpan", nil)
}

// TestCloudflare godoc
// POST /api/v1/settings/cloudflare/test   [Admin+]
func (h *SettingsHandler) TestCloudflare(w http.ResponseWriter, r *http.Request, _ []string) {
	result, err := h.settingsSvc.TestCloudflareConnection(r.Context())
	if err != nil {
		handleServiceError(w, err)
		return
	}
	if result.Success {
		core.Success(w, "Koneksi Cloudflare berhasil", result)
	} else {
		core.Error(w, http.StatusBadGateway, result.Message)
	}
}

// DiscoverZones godoc
// GET /api/v1/settings/cloudflare/zones   [Admin+]
// Query: api_token (opsional) — jika tidak diberikan, gunakan token tersimpan
func (h *SettingsHandler) DiscoverZones(w http.ResponseWriter, r *http.Request, _ []string) {
	inputToken := r.URL.Query().Get("api_token")
	zones, err := h.settingsSvc.DiscoverCloudflareZones(r.Context(), inputToken)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	if zones == nil {
		zones = []*domain.CloudflareZone{}
	}
	core.Success(w, "Daftar zone Cloudflare", zones)
}

// SetACME godoc
// PUT /api/v1/settings/acme   [SuperAdmin]
// Body: {"email":"...","staging":false}
func (h *SettingsHandler) SetACME(w http.ResponseWriter, r *http.Request, _ []string) {
	var req struct {
		Email   string `json:"email"`
		Staging *bool  `json:"staging"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	if req.Email != "" {
		if err := h.settingsSvc.SetACMEEmail(r.Context(), req.Email); err != nil {
			handleServiceError(w, err)
			return
		}
	}
	if req.Staging != nil {
		if err := h.settingsSvc.SetACMEStaging(r.Context(), *req.Staging); err != nil {
			handleServiceError(w, err)
			return
		}
	}
	core.Success(w, "ACME settings berhasil disimpan", nil)
}

// GetACME godoc
// GET /api/v1/settings/acme   [Admin+]
func (h *SettingsHandler) GetACME(w http.ResponseWriter, r *http.Request, _ []string) {
	email, _ := h.settingsSvc.GetACMEEmail(r.Context())
	staging, _ := h.settingsSvc.IsACMEStaging(r.Context())
	core.Success(w, "ACME settings", map[string]interface{}{
		"email":   email,
		"staging": staging,
	})
}

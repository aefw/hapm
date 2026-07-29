package handler

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

type WAFCORSHandler struct {
	cfg         *config.Config
	repo        domain.WAFCORSRepository
	settingsSvc domain.SettingsService
}

func RegisterWAFCORSRoutes(
	router *core.Router,
	cfg *config.Config,
	repo domain.WAFCORSRepository,
	settingsSvc domain.SettingsService,
) {
	h := &WAFCORSHandler{cfg: cfg, repo: repo, settingsSvc: settingsSvc}
	router.GET("/api/v1/waf/cors", middleware.RequireAuth(cfg, h.List))
	router.POST("/api/v1/waf/cors", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Create)))
	router.PUT("/api/v1/waf/cors/{id}", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Update)))
	router.DELETE("/api/v1/waf/cors/{id}", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Delete)))
}

// GET /api/v1/waf/cors
func (h *WAFCORSHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()
	featureEnabled, _ := h.settingsSvc.IsWAFEnabled(ctx)

	list, err := h.repo.List(ctx)
	if err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal mengambil CORS rules: "+err.Error())
		return
	}
	if list == nil {
		list = []*domain.WAFCORSRule{}
	}
	core.Success(w, "cors", map[string]interface{}{
		"feature_enabled": featureEnabled,
		"rules":           list,
	})
}

type corsRuleRequest struct {
	Name             string `json:"name"`
	PathPattern      string `json:"path_pattern"`
	AllowedOrigins   string `json:"allowed_origins"`
	AllowedMethods   string `json:"allowed_methods"`
	AllowedHeaders   string `json:"allowed_headers"`
	ExposeHeaders    string `json:"expose_headers"`
	AllowCredentials bool   `json:"allow_credentials"`
	MaxAgeSeconds    int    `json:"max_age_seconds"`
	Enabled          bool   `json:"enabled"`
	Priority         int    `json:"priority"`
}

func (req *corsRuleRequest) validate() string {
	if strings.TrimSpace(req.Name) == "" {
		return "Nama rule tidak boleh kosong"
	}
	if strings.TrimSpace(req.PathPattern) == "" {
		return "Path pattern tidak boleh kosong"
	}
	if _, err := regexp.Compile(req.PathPattern); err != nil {
		return "Path pattern bukan regex yang valid: " + err.Error()
	}
	if strings.TrimSpace(req.AllowedOrigins) == "" {
		return "Allowed origins tidak boleh kosong"
	}
	// Validasi JSON array
	var origins []string
	if err := json.Unmarshal([]byte(req.AllowedOrigins), &origins); err != nil {
		return "allowed_origins harus berupa JSON array (contoh: [\"https://app.example.com\"])"
	}
	// Security: tidak boleh wildcard jika credentials=true
	if req.AllowCredentials {
		for _, o := range origins {
			if o == "*" {
				return "allow_credentials tidak bisa dikombinasikan dengan origin wildcard (*)"
			}
		}
	}
	if req.MaxAgeSeconds < 0 {
		return "max_age_seconds tidak boleh negatif"
	}
	return ""
}

// POST /api/v1/waf/cors
func (h *WAFCORSHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()

	enabled, _ := h.settingsSvc.IsWAFEnabled(ctx)
	if !enabled {
		core.Error(w, http.StatusForbidden, "Fitur WAF tidak aktif.")
		return
	}

	var req corsRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}
	if msg := req.validate(); msg != "" {
		core.Error(w, http.StatusBadRequest, msg)
		return
	}

	maxAge := req.MaxAgeSeconds
	if maxAge == 0 {
		maxAge = 3600
	}

	rule := &domain.WAFCORSRule{
		Name:             strings.TrimSpace(req.Name),
		PathPattern:      strings.TrimSpace(req.PathPattern),
		AllowedOrigins:   req.AllowedOrigins,
		AllowedMethods:   req.AllowedMethods,
		AllowedHeaders:   req.AllowedHeaders,
		ExposeHeaders:    req.ExposeHeaders,
		AllowCredentials: req.AllowCredentials,
		MaxAgeSeconds:    maxAge,
		Enabled:          req.Enabled,
		Priority:         req.Priority,
	}
	if err := h.repo.Create(ctx, rule); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menyimpan CORS rule: "+err.Error())
		return
	}
	core.Success(w, "cors_rule", rule)
}

// PUT /api/v1/waf/cors/{id}
func (h *WAFCORSHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
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

	rule, err := h.repo.FindByID(ctx, id)
	if err != nil {
		core.Error(w, http.StatusNotFound, "CORS rule tidak ditemukan")
		return
	}

	var req corsRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}
	if msg := req.validate(); msg != "" {
		core.Error(w, http.StatusBadRequest, msg)
		return
	}

	rule.Name = strings.TrimSpace(req.Name)
	rule.PathPattern = strings.TrimSpace(req.PathPattern)
	rule.AllowedOrigins = req.AllowedOrigins
	rule.AllowedMethods = req.AllowedMethods
	rule.AllowedHeaders = req.AllowedHeaders
	rule.ExposeHeaders = req.ExposeHeaders
	rule.AllowCredentials = req.AllowCredentials
	rule.MaxAgeSeconds = req.MaxAgeSeconds
	if rule.MaxAgeSeconds == 0 {
		rule.MaxAgeSeconds = 3600
	}
	rule.Enabled = req.Enabled
	rule.Priority = req.Priority

	if err := h.repo.Update(ctx, rule); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal memperbarui CORS rule: "+err.Error())
		return
	}
	core.Success(w, "cors_rule", rule)
}

// DELETE /api/v1/waf/cors/{id}
func (h *WAFCORSHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
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
		core.Error(w, http.StatusNotFound, "CORS rule tidak ditemukan")
		return
	}

	if err := h.repo.Delete(ctx, id); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menghapus CORS rule: "+err.Error())
		return
	}
	core.Success(w, "message", "CORS rule berhasil dihapus")
}

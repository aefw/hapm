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

type WAFRateLimitHandler struct {
	cfg         *config.Config
	repo        domain.WAFRateLimitRepository
	settingsSvc domain.SettingsService
}

func RegisterWAFRateLimitRoutes(
	router *core.Router,
	cfg *config.Config,
	repo domain.WAFRateLimitRepository,
	settingsSvc domain.SettingsService,
) {
	h := &WAFRateLimitHandler{cfg: cfg, repo: repo, settingsSvc: settingsSvc}
	router.GET("/api/v1/waf/rate-limits", middleware.RequireAuth(cfg, h.List))
	router.POST("/api/v1/waf/rate-limits", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Create)))
	router.PUT("/api/v1/waf/rate-limits/{id}", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Update)))
	router.DELETE("/api/v1/waf/rate-limits/{id}", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Delete)))
}

// GET /api/v1/waf/rate-limits
func (h *WAFRateLimitHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()
	featureEnabled, _ := h.settingsSvc.IsWAFEnabled(ctx)

	list, err := h.repo.List(ctx)
	if err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal mengambil rate limit profiles: "+err.Error())
		return
	}
	if list == nil {
		list = []*domain.WAFRateLimit{}
	}
	core.Success(w, "rate_limits", map[string]interface{}{
		"feature_enabled": featureEnabled,
		"profiles":        list,
	})
}

type rateLimitRequest struct {
	Name                   string `json:"name"`
	PathPattern            string `json:"path_pattern"`
	MaxRequests            int    `json:"max_requests"`
	WindowSeconds          int    `json:"window_seconds"`
	BlockDurationSeconds   int    `json:"block_duration_seconds"`
	AutoBlacklistThreshold *int   `json:"auto_blacklist_threshold"`
	Enabled                bool   `json:"enabled"`
}

func (req *rateLimitRequest) validate() string {
	if strings.TrimSpace(req.Name) == "" {
		return "Nama profile tidak boleh kosong"
	}
	if strings.TrimSpace(req.PathPattern) == "" {
		return "Path pattern tidak boleh kosong"
	}
	if _, err := regexp.Compile(req.PathPattern); err != nil {
		return "Path pattern bukan regex yang valid: " + err.Error()
	}
	if req.MaxRequests <= 0 {
		return "max_requests harus lebih dari 0"
	}
	if req.WindowSeconds <= 0 {
		return "window_seconds harus lebih dari 0"
	}
	if req.BlockDurationSeconds <= 0 {
		return "block_duration_seconds harus lebih dari 0"
	}
	return ""
}

// POST /api/v1/waf/rate-limits
func (h *WAFRateLimitHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()

	enabled, _ := h.settingsSvc.IsWAFEnabled(ctx)
	if !enabled {
		core.Error(w, http.StatusForbidden, "Fitur WAF tidak aktif.")
		return
	}

	var req rateLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}
	if msg := req.validate(); msg != "" {
		core.Error(w, http.StatusBadRequest, msg)
		return
	}

	rl := &domain.WAFRateLimit{
		Name:                   strings.TrimSpace(req.Name),
		PathPattern:            strings.TrimSpace(req.PathPattern),
		MaxRequests:            req.MaxRequests,
		WindowSeconds:          req.WindowSeconds,
		BlockDurationSeconds:   req.BlockDurationSeconds,
		AutoBlacklistThreshold: req.AutoBlacklistThreshold,
		Enabled:                req.Enabled,
	}
	if err := h.repo.Create(ctx, rl); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menyimpan rate limit profile: "+err.Error())
		return
	}
	core.Success(w, "rate_limit", rl)
}

// PUT /api/v1/waf/rate-limits/{id}
func (h *WAFRateLimitHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
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

	rl, err := h.repo.FindByID(ctx, id)
	if err != nil {
		core.Error(w, http.StatusNotFound, "Rate limit profile tidak ditemukan")
		return
	}

	var req rateLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}
	if msg := req.validate(); msg != "" {
		core.Error(w, http.StatusBadRequest, msg)
		return
	}

	rl.Name = strings.TrimSpace(req.Name)
	rl.PathPattern = strings.TrimSpace(req.PathPattern)
	rl.MaxRequests = req.MaxRequests
	rl.WindowSeconds = req.WindowSeconds
	rl.BlockDurationSeconds = req.BlockDurationSeconds
	rl.AutoBlacklistThreshold = req.AutoBlacklistThreshold
	rl.Enabled = req.Enabled

	if err := h.repo.Update(ctx, rl); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal memperbarui rate limit profile: "+err.Error())
		return
	}
	core.Success(w, "rate_limit", rl)
}

// DELETE /api/v1/waf/rate-limits/{id}
func (h *WAFRateLimitHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
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
		core.Error(w, http.StatusNotFound, "Rate limit profile tidak ditemukan")
		return
	}

	if err := h.repo.Delete(ctx, id); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menghapus rate limit profile: "+err.Error())
		return
	}
	core.Success(w, "message", "Rate limit profile berhasil dihapus")
}

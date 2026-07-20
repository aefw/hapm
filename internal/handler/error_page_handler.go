package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

type ErrorPageHandler struct {
	cfg         *config.Config
	repo        domain.ErrorPageRepository
	settingsSvc domain.SettingsService
}

func RegisterErrorPageRoutes(
	router *core.Router,
	cfg *config.Config,
	repo domain.ErrorPageRepository,
	settingsSvc domain.SettingsService,
) {
	h := &ErrorPageHandler{cfg: cfg, repo: repo, settingsSvc: settingsSvc}
	router.GET("/api/v1/error-pages", middleware.RequireAuth(cfg, h.List))
	router.PUT("/api/v1/error-pages/{code}", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Update)))
	// Feature toggle — path terpisah untuk menghindari konflik dengan /{code}
	router.GET("/api/v1/settings/features/error-pages", middleware.RequireAuth(cfg, h.GetFeature))
	router.PUT("/api/v1/settings/features/error-pages", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.SetFeature)))
}

// GET /api/v1/error-pages
// Mengembalikan semua error pages beserta status fitur premium.
func (h *ErrorPageHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()

	featureEnabled, _ := h.settingsSvc.IsCustomErrorPagesEnabled(ctx)

	pages, err := h.repo.List(ctx)
	if err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal mengambil error pages: "+err.Error())
		return
	}

	core.Success(w, "error_pages", map[string]interface{}{
		"feature_enabled": featureEnabled,
		"pages":           pages,
	})
}

type updateErrorPageRequest struct {
	Content string `json:"content"`
}

// PUT /api/v1/error-pages/{code}
// Update konten dan status aktif untuk satu error code.
// Fitur harus aktif sebelum bisa menyimpan perubahan.
func (h *ErrorPageHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
	ctx := r.Context()

	code, err := strconv.Atoi(params[0])
	if err != nil {
		core.Error(w, http.StatusBadRequest, "Error code tidak valid")
		return
	}

	featureEnabled, _ := h.settingsSvc.IsCustomErrorPagesEnabled(ctx)
	if !featureEnabled {
		core.Error(w, http.StatusForbidden, "Fitur Custom Error Pages tidak aktif. Aktifkan terlebih dahulu di Settings → Features.")
		return
	}

	var req updateErrorPageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}

	if strings.TrimSpace(req.Content) == "" {
		core.Error(w, http.StatusBadRequest, "Konten tidak boleh kosong")
		return
	}

	ep, err := h.repo.FindByCode(ctx, code)
	if err != nil {
		core.Error(w, http.StatusNotFound, "Error code tidak ditemukan: "+strconv.Itoa(code))
		return
	}

	ep.Content = strings.TrimSpace(req.Content)
	ep.Enabled = true

	if err := h.repo.Update(ctx, ep); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menyimpan error page: "+err.Error())
		return
	}

	core.Success(w, "error_page", ep)
}

// GET /api/v1/settings/features/error-pages
// Mengembalikan status fitur custom error pages.
func (h *ErrorPageHandler) GetFeature(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()
	enabled, _ := h.settingsSvc.IsCustomErrorPagesEnabled(ctx)
	core.Success(w, "feature", map[string]interface{}{
		"key":     "custom_error_pages",
		"enabled": enabled,
	})
}

type setFeatureRequest struct {
	Enabled bool `json:"enabled"`
}

// PUT /api/v1/settings/features/error-pages
// Toggle fitur custom error pages. Hanya superadmin.
func (h *ErrorPageHandler) SetFeature(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()

	var req setFeatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}

	if err := h.settingsSvc.SetCustomErrorPagesEnabled(ctx, req.Enabled); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal mengubah status fitur: "+err.Error())
		return
	}

	core.Success(w, "feature", map[string]interface{}{
		"key":     "custom_error_pages",
		"enabled": req.Enabled,
	})
}

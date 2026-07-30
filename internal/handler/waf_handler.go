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

type WAFHandler struct {
	cfg         *config.Config
	repo        domain.WAFRuleRepository
	settingsSvc domain.SettingsService
	snSvc       domain.SNService
}

func RegisterWAFRoutes(
	router *core.Router,
	cfg *config.Config,
	repo domain.WAFRuleRepository,
	settingsSvc domain.SettingsService,
	snSvc domain.SNService,
) {
	h := &WAFHandler{cfg: cfg, repo: repo, settingsSvc: settingsSvc, snSvc: snSvc}
	router.GET("/api/v1/waf/rules", middleware.RequireAuth(cfg, h.List))
	router.POST("/api/v1/waf/rules", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Create)))
	router.PUT("/api/v1/waf/rules/{id}", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Update)))
	router.DELETE("/api/v1/waf/rules/{id}", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Delete)))
	router.GET("/api/v1/settings/features/waf", middleware.RequireAuth(cfg, h.GetFeature))
	router.PUT("/api/v1/settings/features/waf", middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.SetFeature)))
}

// GET /api/v1/waf/rules
func (h *WAFHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()

	featureEnabled, _ := h.settingsSvc.IsWAFEnabled(ctx)

	rules, err := h.repo.List(ctx)
	if err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal mengambil WAF rules: "+err.Error())
		return
	}

	if rules == nil {
		rules = []*domain.WAFRule{}
	}

	core.Success(w, "waf", map[string]interface{}{
		"feature_enabled": featureEnabled,
		"rules":           rules,
	})
}

type wafRuleRequest struct {
	Name      string `json:"name"`
	RuleType  string `json:"rule_type"`
	Value     string `json:"value"`
	Action    string `json:"action"`
	Enabled   bool   `json:"enabled"`
	DomainIDs []int  `json:"domain_ids"`
}

func (req *wafRuleRequest) validate() string {
	if strings.TrimSpace(req.Name) == "" {
		return "Nama rule tidak boleh kosong"
	}
	if strings.TrimSpace(req.Value) == "" {
		return "Nilai rule tidak boleh kosong"
	}
	validTypes := map[string]bool{"ip_block": true, "path_block": true, "ua_block": true, "header_block": true}
	if !validTypes[req.RuleType] {
		return "Tipe rule tidak valid (ip_block, path_block, ua_block, header_block)"
	}
	validActions := map[string]bool{"deny": true, "allow": true}
	if !validActions[req.Action] {
		return "Action tidak valid (deny, allow)"
	}
	return ""
}

// POST /api/v1/waf/rules
func (h *WAFHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()

	featureEnabled, _ := h.settingsSvc.IsWAFEnabled(ctx)
	if !featureEnabled {
		core.Error(w, http.StatusForbidden, "Fitur WAF tidak aktif. Aktifkan terlebih dahulu di Settings → Features.")
		return
	}

	var req wafRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}
	if msg := req.validate(); msg != "" {
		core.Error(w, http.StatusBadRequest, msg)
		return
	}

	rule := &domain.WAFRule{
		Name:      strings.TrimSpace(req.Name),
		RuleType:  req.RuleType,
		Value:     strings.TrimSpace(req.Value),
		Action:    req.Action,
		Enabled:   req.Enabled,
		DomainIDs: req.DomainIDs,
	}
	if err := h.repo.Create(ctx, rule); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menyimpan WAF rule: "+err.Error())
		return
	}

	core.Success(w, "rule", rule)
}

// PUT /api/v1/waf/rules/{id}
func (h *WAFHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
	ctx := r.Context()

	featureEnabled, _ := h.settingsSvc.IsWAFEnabled(ctx)
	if !featureEnabled {
		core.Error(w, http.StatusForbidden, "Fitur WAF tidak aktif. Aktifkan terlebih dahulu di Settings → Features.")
		return
	}

	id, err := strconv.Atoi(params[0])
	if err != nil {
		core.Error(w, http.StatusBadRequest, "ID rule tidak valid")
		return
	}

	rule, err := h.repo.FindByID(ctx, id)
	if err != nil {
		core.Error(w, http.StatusNotFound, "WAF rule tidak ditemukan")
		return
	}

	var req wafRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}
	if msg := req.validate(); msg != "" {
		core.Error(w, http.StatusBadRequest, msg)
		return
	}

	rule.Name = strings.TrimSpace(req.Name)
	rule.RuleType = req.RuleType
	rule.Value = strings.TrimSpace(req.Value)
	rule.Action = req.Action
	rule.Enabled = req.Enabled
	rule.DomainIDs = req.DomainIDs

	if err := h.repo.Update(ctx, rule); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal memperbarui WAF rule: "+err.Error())
		return
	}

	core.Success(w, "rule", rule)
}

// DELETE /api/v1/waf/rules/{id}
func (h *WAFHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	ctx := r.Context()

	featureEnabled, _ := h.settingsSvc.IsWAFEnabled(ctx)
	if !featureEnabled {
		core.Error(w, http.StatusForbidden, "Fitur WAF tidak aktif.")
		return
	}

	id, err := strconv.Atoi(params[0])
	if err != nil {
		core.Error(w, http.StatusBadRequest, "ID rule tidak valid")
		return
	}

	if _, err := h.repo.FindByID(ctx, id); err != nil {
		core.Error(w, http.StatusNotFound, "WAF rule tidak ditemukan")
		return
	}

	if err := h.repo.Delete(ctx, id); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal menghapus WAF rule: "+err.Error())
		return
	}

	core.Success(w, "message", "WAF rule berhasil dihapus")
}

// GET /api/v1/settings/features/waf
func (h *WAFHandler) GetFeature(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()
	enabled, _ := h.settingsSvc.IsWAFEnabled(ctx)
	core.Success(w, "feature", map[string]interface{}{
		"key":     "waf",
		"enabled": enabled,
	})
}

type wafSetFeatureRequest struct {
	Enabled bool `json:"enabled"`
}

// PUT /api/v1/settings/features/waf
func (h *WAFHandler) SetFeature(w http.ResponseWriter, r *http.Request, _ []string) {
	ctx := r.Context()

	var req wafSetFeatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.Error(w, http.StatusBadRequest, "Request body tidak valid")
		return
	}

	if req.Enabled {
		status, err := h.snSvc.Status(ctx)
		if err != nil || !status.HasFile || !status.IsValid || status.IsExpired || !status.HasModule {
			core.Error(w, http.StatusForbidden, "Fitur WAF memerlukan lisensi aktif. Aktifkan lisensi terlebih dahulu.")
			return
		}
	}

	if err := h.settingsSvc.SetWAFEnabled(ctx, req.Enabled); err != nil {
		core.Error(w, http.StatusInternalServerError, "Gagal mengubah status fitur WAF: "+err.Error())
		return
	}

	core.Success(w, "feature", map[string]interface{}{
		"key":     "waf",
		"enabled": req.Enabled,
	})
}

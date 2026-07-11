package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// AuditHandler menangani semua endpoint audit log.
type AuditHandler struct {
	svc domain.AuditService
	cfg *config.Config
}

// RegisterAuditRoutes mendaftarkan semua route audit ke router.
func RegisterAuditRoutes(router *core.Router, cfg *config.Config, svc domain.AuditService) {
	h := &AuditHandler{svc: svc, cfg: cfg}

	// Daftar audit log dengan filter query params
	router.GET("/api/v1/audit",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.List)))

	// Detail satu audit log
	router.GET("/api/v1/audit/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.GetByID)))
}

// List godoc
// GET /api/v1/audit   [Admin+]
// Query params:
//   - q        string — keyword pencarian (action, resource_type, detail)
//   - user_id  int    — filter by user
//   - action   string — filter by action (e.g. user.login)
//   - resource string — filter by resource type (e.g. node)
//   - from     string — RFC3339 start date
//   - to       string — RFC3339 end date
//   - start    int    — offset pagination (default 0)
//   - limit    int    — max results (default 10, max 500)
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	q := r.URL.Query()
	filter := domain.AuditFilter{
		Q:            q.Get("q"),
		Action:       q.Get("action"),
		ResourceType: q.Get("resource"),
		Limit:        10,
		Start:        0,
	}

	if uid := q.Get("user_id"); uid != "" {
		if id, err := strconv.Atoi(uid); err == nil && id > 0 {
			filter.UserID = &id
		}
	}
	if l := q.Get("limit"); l != "" {
		if lv, err := strconv.Atoi(l); err == nil && lv > 0 {
			filter.Limit = lv
			if filter.Limit > 500 {
				filter.Limit = 500
			}
		}
	}
	if s := q.Get("start"); s != "" {
		if sv, err := strconv.Atoi(s); err == nil && sv >= 0 {
			filter.Start = sv
		}
	}
	if from := q.Get("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			filter.FromDate = &t
		}
	}
	if to := q.Get("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			filter.ToDate = &t
		}
	}

	logs, total, err := h.svc.List(r.Context(), filter)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	if logs == nil {
		logs = []*domain.AuditLog{}
	}
	type listResult struct {
		Total int                `json:"total"`
		Start int                `json:"start"`
		Limit int                `json:"limit"`
		Items []*domain.AuditLog `json:"items"`
	}
	core.Success(w, "Daftar audit log", &listResult{
		Total: total,
		Start: filter.Start,
		Limit: filter.Limit,
		Items: logs,
	})
}

// GetByID godoc
// GET /api/v1/audit/{id}   [Admin+]
func (h *AuditHandler) GetByID(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID audit log tidak valid")
		return
	}

	log, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Detail audit log", log)
}

package handler

import (
	"encoding/json"
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// AuthUserMgmtHandler menangani CRUD auth user HAProxy userlist.
type AuthUserMgmtHandler struct {
	svc domain.AuthUserService
	cfg *config.Config
}

// AuthGroupMgmtHandler menangani CRUD auth group dan member management.
type AuthGroupMgmtHandler struct {
	svc domain.AuthGroupService
	cfg *config.Config
}

// RegisterHAProxyAuthRoutes mendaftarkan route auth-users dan auth-groups.
func RegisterHAProxyAuthRoutes(router *core.Router, cfg *config.Config, userSvc domain.AuthUserService, groupSvc domain.AuthGroupService) {
	uh := &AuthUserMgmtHandler{svc: userSvc, cfg: cfg}
	gh := &AuthGroupMgmtHandler{svc: groupSvc, cfg: cfg}

	// Auth Users
	router.GET("/api/v1/auth-users",
		middleware.RequireAuth(cfg, uh.List))
	router.POST("/api/v1/auth-users",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, uh.Create)))
	router.GET("/api/v1/auth-users/{id}",
		middleware.RequireAuth(cfg, uh.GetByID))
	router.PUT("/api/v1/auth-users/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, uh.Update)))
	router.DELETE("/api/v1/auth-users/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, uh.Delete)))

	// Auth Groups
	router.GET("/api/v1/auth-groups",
		middleware.RequireAuth(cfg, gh.List))
	router.POST("/api/v1/auth-groups",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, gh.Create)))
	router.GET("/api/v1/auth-groups/{id}",
		middleware.RequireAuth(cfg, gh.GetByID))
	router.PUT("/api/v1/auth-groups/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, gh.Update)))
	router.DELETE("/api/v1/auth-groups/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, gh.Delete)))

	// Group Members
	router.GET("/api/v1/auth-groups/{id}/members",
		middleware.RequireAuth(cfg, gh.ListMembers))
	router.POST("/api/v1/auth-groups/{id}/members",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, gh.AddMember)))
	router.DELETE("/api/v1/auth-groups/{id}/members/{userID}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, gh.RemoveMember)))
}

// ─── AuthUserMgmtHandler ──────────────────────────────────────────────────────

func (h *AuthUserMgmtHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	f := parseListFilter(r)
	users, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	respondList(w, "Daftar auth user", users, total, f)
}

func (h *AuthUserMgmtHandler) GetByID(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID auth user tidak valid")
		return
	}
	u, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Data auth user", u)
}

func (h *AuthUserMgmtHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.CreateAuthUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	u, err := h.svc.Create(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Auth user berhasil ditambahkan", u)
}

func (h *AuthUserMgmtHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID auth user tidak valid")
		return
	}
	var req domain.CreateAuthUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	u, err := h.svc.Update(r.Context(), id, &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Auth user berhasil diupdate", u)
}

func (h *AuthUserMgmtHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID auth user tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	if err := h.svc.Delete(r.Context(), id, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Auth user berhasil dihapus", nil)
}

// ─── AuthGroupMgmtHandler ─────────────────────────────────────────────────────

func (h *AuthGroupMgmtHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	f := parseListFilter(r)
	groups, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	respondList(w, "Daftar auth group", groups, total, f)
}

func (h *AuthGroupMgmtHandler) GetByID(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID auth group tidak valid")
		return
	}
	g, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Data auth group", g)
}

func (h *AuthGroupMgmtHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.CreateAuthGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	g, err := h.svc.Create(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "Auth group berhasil ditambahkan", g)
}

func (h *AuthGroupMgmtHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID auth group tidak valid")
		return
	}
	var req domain.CreateAuthGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	g, err := h.svc.Update(r.Context(), id, &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Auth group berhasil diupdate", g)
}

func (h *AuthGroupMgmtHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID auth group tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	if err := h.svc.Delete(r.Context(), id, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Auth group berhasil dihapus", nil)
}

func (h *AuthGroupMgmtHandler) ListMembers(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID auth group tidak valid")
		return
	}
	members, err := h.svc.ListMembers(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	if members == nil {
		members = []*domain.AuthUser{}
	}
	core.Success(w, "Daftar member group", members)
}

func (h *AuthGroupMgmtHandler) AddMember(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID auth group tidak valid")
		return
	}
	var req domain.AddGroupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}
	if req.AuthUserID <= 0 {
		core.BadRequest(w, "id_auth_users wajib diisi")
		return
	}
	actorID := core.GetUserID(r.Context())
	if err := h.svc.AddMember(r.Context(), id, &req, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Member berhasil ditambahkan ke group", nil)
}

func (h *AuthGroupMgmtHandler) RemoveMember(w http.ResponseWriter, r *http.Request, params []string) {
	groupID, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID auth group tidak valid")
		return
	}
	userID, ok := parseID(params, 1)
	if !ok {
		core.BadRequest(w, "ID auth user tidak valid")
		return
	}
	actorID := core.GetUserID(r.Context())
	if err := h.svc.RemoveMember(r.Context(), groupID, userID, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Member berhasil dihapus dari group", nil)
}

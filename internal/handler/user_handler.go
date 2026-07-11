package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// UserHandler menangani semua endpoint manajemen user.
type UserHandler struct {
	svc domain.UserService
	cfg *config.Config
}

// RegisterUserRoutes mendaftarkan semua route user ke router.
// Semua route memerlukan autentikasi.
// GET/POST list: admin+
// GET/PUT/DELETE by ID: admin+ (atau user sendiri untuk GET)
// Lock/Unlock: superadmin only
func RegisterUserRoutes(router *core.Router, cfg *config.Config, svc domain.UserService) {
	h := &UserHandler{svc: svc, cfg: cfg}

	// List & Create — admin+
	router.GET("/api/v1/users",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.List)))
	router.POST("/api/v1/users",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Create)))

	// Get by ID — admin+ (user sendiri bisa lihat profil sendiri via /auth/me)
	router.GET("/api/v1/users/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.GetByID)))
	router.PUT("/api/v1/users/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleAdmin, h.Update)))
	router.DELETE("/api/v1/users/{id}",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.Delete)))

	// Lock/Unlock — superadmin only
	router.PUT("/api/v1/users/{id}/lock",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.Lock)))
	router.PUT("/api/v1/users/{id}/unlock",
		middleware.RequireAuth(cfg, middleware.RequireRole(middleware.RoleSuperAdmin, h.Unlock)))
}

// List godoc
// GET /api/v1/users   [Admin+]
// Query: q=keyword, start=0, limit=50
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request, _ []string) {
	f := parseListFilter(r)
	users, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	respondList(w, "Daftar user", users, total, f)
}

// GetByID godoc
// GET /api/v1/users/{id}   [Admin+]
func (h *UserHandler) GetByID(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID user tidak valid")
		return
	}

	user, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Data user", user)
}

// Create godoc
// POST /api/v1/users   [Admin+]
// Body: {"username":"...","email":"...","password":"...","full_name":"...","role":"..."}
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	user, err := h.svc.Create(r.Context(), &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Created(w, "User berhasil dibuat", user)
}

// Update godoc
// PUT /api/v1/users/{id}   [Admin+]
// Body: {"email":"...","full_name":"...","role":"...","active":true}
func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID user tidak valid")
		return
	}

	var req domain.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	user, err := h.svc.Update(r.Context(), id, &req, actorID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "User berhasil diupdate", user)
}

// Delete godoc
// DELETE /api/v1/users/{id}   [SuperAdmin]
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID user tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	if err := h.svc.Delete(r.Context(), id, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "User berhasil dihapus", nil)
}

// Lock godoc
// PUT /api/v1/users/{id}/lock   [SuperAdmin]
func (h *UserHandler) Lock(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID user tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	if err := h.svc.SetLocked(r.Context(), id, true, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "User berhasil dikunci", map[string]string{"id": strconv.Itoa(id), "locked": "true"})
}

// Unlock godoc
// PUT /api/v1/users/{id}/unlock   [SuperAdmin]
func (h *UserHandler) Unlock(w http.ResponseWriter, r *http.Request, params []string) {
	id, ok := parseID(params, 0)
	if !ok {
		core.BadRequest(w, "ID user tidak valid")
		return
	}

	actorID := core.GetUserID(r.Context())
	if err := h.svc.SetLocked(r.Context(), id, false, actorID); err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "User berhasil dibuka kuncinya", map[string]string{"id": strconv.Itoa(id), "locked": "false"})
}

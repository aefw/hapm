package handler

import (
	"encoding/json"
	"net/http"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// AuthHandler menangani semua endpoint autentikasi.
type AuthHandler struct {
	svc domain.AuthService
	cfg *config.Config
}

// NewAuthHandler membuat instance AuthHandler.
func NewAuthHandler(cfg *config.Config, svc domain.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc, cfg: cfg}
}

// RegisterAuthRoutes mendaftarkan semua route autentikasi ke router.
// Signature: RegisterAuthRoutes(router, cfg, svc)
// Route publik: POST /login, POST /refresh
// Route protected: POST /logout, PUT /change-password
func RegisterAuthRoutes(router *core.Router, cfg *config.Config, svc domain.AuthService) {
	h := NewAuthHandler(cfg, svc)

	// Publik — tidak butuh auth
	router.POST("/api/v1/auth/login", h.Login)
	router.POST("/api/v1/auth/refresh", h.Refresh)

	// Protected — butuh JWT
	router.GET("/api/v1/auth/me", middleware.RequireAuth(cfg, h.Me))
	router.POST("/api/v1/auth/logout", middleware.RequireAuth(cfg, h.Logout))
	router.PUT("/api/v1/auth/change-password", middleware.RequireAuth(cfg, h.ChangePassword))
}

// Login godoc
// POST /api/v1/auth/login
// Body: {"username":"...","password":"..."}
// Response: {"access_token":"...","refresh_token":"...","expires_in":900,"user":{...}}
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	if req.Username == "" || req.Password == "" {
		core.BadRequest(w, "Username dan password wajib diisi")
		return
	}

	resp, err := h.svc.Login(r.Context(), r, &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	core.Success(w, "Login berhasil", resp)
}

// Refresh godoc
// POST /api/v1/auth/refresh
// Body: {"refresh_token":"..."}
// Response: {"access_token":"...","refresh_token":"...","expires_in":900}
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request, _ []string) {
	var req domain.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	if req.RefreshToken == "" {
		core.BadRequest(w, "refresh_token wajib diisi")
		return
	}

	resp, err := h.svc.RefreshToken(r.Context(), &req)
	if err != nil {
		handleServiceError(w, err)
		return
	}

	core.Success(w, "Token diperbarui", resp)
}

// Logout godoc
// POST /api/v1/auth/logout   [Auth Required]
// Body: {"refresh_token":"..."}
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request, _ []string) {
	userID := core.GetUserID(r.Context())

	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	if err := h.svc.Logout(r.Context(), userID, body.RefreshToken); err != nil {
		handleServiceError(w, err)
		return
	}

	core.Success(w, "Logout berhasil", nil)
}

// Me godoc
// GET /api/v1/auth/me   [Auth Required]
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request, _ []string) {
	userID := core.GetUserID(r.Context())
	user, err := h.svc.GetMe(r.Context(), userID)
	if err != nil {
		handleServiceError(w, err)
		return
	}
	core.Success(w, "Profil user", user)
}

// ChangePassword godoc
// PUT /api/v1/auth/change-password   [Auth Required]
// Body: {"old_password":"...","new_password":"..."}
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request, _ []string) {
	userID := core.GetUserID(r.Context())

	var req domain.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Body request tidak valid")
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		core.BadRequest(w, "old_password dan new_password wajib diisi")
		return
	}

	if err := h.svc.ChangePassword(r.Context(), userID, &req); err != nil {
		handleServiceError(w, err)
		return
	}

	core.Success(w, "Password berhasil diubah", nil)
}

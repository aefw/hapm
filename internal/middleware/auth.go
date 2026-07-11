package middleware

import (
	"net/http"
	"strings"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/security"
)

// RequireAuth membungkus HandlerFunc dengan validasi JWT access token.
// Token diambil dari header: Authorization: Bearer <token>
// Jika valid, user info (user_id, username, role) di-set ke context.
//
// Digunakan per-route agar endpoint publik seperti /login tidak terkena auth.
func RequireAuth(cfg *config.Config, handler core.HandlerFunc) core.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params []string) {
		tokenStr, ok := extractBearerToken(r)
		if !ok {
			core.Unauthorized(w, "Token tidak ditemukan atau format tidak valid")
			return
		}

		claims, err := security.ValidateToken(tokenStr, cfg.JWT.AccessSecret)
		if err != nil {
			core.Unauthorized(w, "Token tidak valid atau sudah expired")
			return
		}

		ctx := core.SetUserContext(r.Context(), claims.UserID, claims.Username, claims.Role)
		handler(w, r.WithContext(ctx), params)
	}
}

// extractBearerToken mengambil token dari "Authorization: Bearer <token>".
// Mengembalikan token string dan true jika valid, atau "" dan false jika tidak.
func extractBearerToken(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", false
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", false
	}
	return token, true
}

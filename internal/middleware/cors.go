package middleware

import (
	"net/http"
	"strings"

	"github.com/aefw/hapm/internal/config"
)

// NewCORSMiddleware menangani Cross-Origin Resource Sharing (CORS).
// Mendukung preflight request (OPTIONS) dan menyetel header CORS yang tepat.
//
// Perilaku berdasarkan mode:
//   - production: hanya izinkan origin dari APP_BASE_URL, dengan credentials support
//   - development: izinkan semua origin (*), tanpa credentials (browser tidak izinkan keduanya)
func NewCORSMiddleware(next http.Handler, cfg *config.Config) http.Handler {
	allowedOrigins := resolveAllowedOrigins(cfg)
	isProd := cfg.App.Mode == "production"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if isProd {
			// Production: specific origin + credentials
			if isOriginAllowed(origin, allowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		} else {
			// Development: wildcard, tapi TANPA credentials
			// Browser melarang kombinasi Access-Control-Allow-Origin: * + credentials: true
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-Real-IP")
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.Header().Set("Vary", "Origin")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func resolveAllowedOrigins(cfg *config.Config) []string {
	if cfg.App.BaseURL == "" {
		return []string{}
	}
	return []string{strings.TrimRight(cfg.App.BaseURL, "/")}
}

func isOriginAllowed(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}
	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

package middleware

import (
	"net/http"
	"strings"
)

// cspAPI dipakai untuk endpoint /api/* — sangat restrictive, tidak ada resource loading.
const cspAPI = "default-src 'none'"

// cspUI dipakai untuk frontend SPA — izinkan script/style/font/img dari origin sendiri.
// unsafe-inline dibutuhkan Framework7 untuk dynamic inline styles.
const cspUI = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self' data:; " +
	"connect-src 'self'; " +
	"manifest-src 'self'"

// NewSecurityHeadersMiddleware menyetel HTTP security headers ke setiap response.
// CSP dibedakan antara route API (/api/*) dan route frontend.
func NewSecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Del("Server")

		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Security-Policy", cspAPI)
		} else {
			w.Header().Set("Content-Security-Policy", cspUI)
		}

		next.ServeHTTP(w, r)
	})
}

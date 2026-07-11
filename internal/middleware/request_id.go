package middleware

import (
	"net/http"

	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/security"
)

// NewRequestIDMiddleware menyisipkan unique request ID ke setiap request.
// Request ID diambil dari header X-Request-ID jika ada, atau digenerate baru.
// Selalu di-set di response header agar mudah di-trace di log / monitoring.
func NewRequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			var err error
			reqID, err = security.RandomHex(8) // 16 karakter hex
			if err != nil {
				reqID = "unknown"
			}
		}

		// Set ke context agar bisa diakses handler dan middleware lain
		ctx := core.SetRequestID(r.Context(), reqID)
		r = r.WithContext(ctx)

		// Set di response header untuk tracing oleh klien
		w.Header().Set("X-Request-ID", reqID)

		next.ServeHTTP(w, r)
	})
}

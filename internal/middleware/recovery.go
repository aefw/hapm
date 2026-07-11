package middleware

import (
	"log"
	"net/http"
	"runtime/debug"

	"github.com/aefw/hapm/internal/core"
)

// NewRecoveryMiddleware menangkap panic yang tidak tertangkap dan mengembalikan
// HTTP 500 daripada membiarkan server crash.
// Stack trace di-log server-side, TIDAK dikirim ke client.
func NewRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				reqID := core.GetRequestID(r.Context())
				log.Printf("[PANIC] req_id=%s path=%s panic=%v\n%s",
					reqID, r.URL.Path, rec, debug.Stack())
				core.InternalError(w, "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

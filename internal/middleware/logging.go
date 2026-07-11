package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/pkg/iputil"
)

// responseWriter adalah wrapper http.ResponseWriter yang menangkap status code dan ukuran response.
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// NewLoggingMiddleware mencatat setiap HTTP request beserta IP client dan sumbernya.
//
// Format log:
//
//	[REQ] METHOD /path status=200 dur=1.23ms size=512B req_id=abc ip=1.2.3.4 src=cloudflare
//
// Kolom src: "cloudflare" | "proxy" | "direct" — membantu membedakan traffic
// dari Cloudflare vs intranet vs koneksi langsung.
func NewLoggingMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	proxyMode := iputil.Mode(cfg.Proxy.Mode)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{
			ResponseWriter: w,
			status:         http.StatusOK,
		}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		reqID := core.GetRequestID(r.Context())
		ip := iputil.RealIP(r, proxyMode)
		src := iputil.SourceLabel(r, proxyMode)

		log.Printf("[REQ] %s %s status=%d dur=%s size=%dB req_id=%s ip=%s src=%s",
			r.Method,
			r.URL.Path,
			rw.status,
			duration.Round(time.Microsecond),
			rw.size,
			reqID,
			ip,
			src,
		)
	})
}

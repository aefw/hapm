package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/pkg/iputil"
)

// windowEntry menyimpan timestamp request dalam sliding window per IP
type windowEntry struct {
	mu   sync.Mutex
	hits []time.Time
}

// rateLimiter adalah in-memory sliding window rate limiter per IP
type rateLimiter struct {
	mu      sync.RWMutex
	entries map[string]*windowEntry
	limit   int
	window  time.Duration
	mode    iputil.Mode
}

// NewAPIRateLimitMiddleware membatasi jumlah request per IP per menit (sliding window).
// Konfigurasi via APP_RATE_LIMIT_API. Set 0 untuk menonaktifkan.
//
// Algoritma: sliding window — hanya request dalam 60 detik terakhir yang dihitung.
// Thread-safe via per-IP mutex untuk mengurangi lock contention.
func NewAPIRateLimitMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	limit := cfg.RateLimit.APIPerMinute
	if limit <= 0 {
		return next
	}

	rl := &rateLimiter{
		entries: make(map[string]*windowEntry),
		limit:   limit,
		window:  time.Minute,
		mode:    iputil.Mode(cfg.Proxy.Mode),
	}

	// Background cleanup: buang entry IP yang sudah lama tidak aktif (setiap 5 menit)
	go rl.cleanup()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := iputil.RealIP(r, rl.mode)

		if rl.isLimited(ip) {
			w.Header().Set("Retry-After", "60")
			core.TooManyRequests(w, "Terlalu banyak request, coba lagi dalam 60 detik")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *rateLimiter) isLimited(ip string) bool {
	rl.mu.RLock()
	entry, exists := rl.entries[ip]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check setelah write lock
		entry, exists = rl.entries[ip]
		if !exists {
			entry = &windowEntry{}
			rl.entries[ip] = entry
		}
		rl.mu.Unlock()
	}

	now := time.Now()
	cutoff := now.Add(-rl.window)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Buang hit yang sudah di luar window
	valid := entry.hits[:0]
	for _, t := range entry.hits {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	entry.hits = valid

	return len(valid) > rl.limit
}

// cleanup membersihkan entry IP yang tidak aktif lebih dari 5 menit
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-5 * time.Minute)
		rl.mu.Lock()
		for ip, entry := range rl.entries {
			entry.mu.Lock()
			if len(entry.hits) == 0 || entry.hits[len(entry.hits)-1].Before(cutoff) {
				delete(rl.entries, ip)
			}
			entry.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

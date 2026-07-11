package iputil

import (
	"net"
	"net/http"
	"strings"
)

// Mode menentukan cara pengambilan IP client berdasarkan topologi jaringan.
type Mode string

const (
	// ModeDirect: tidak ada proxy — gunakan RemoteAddr langsung
	ModeDirect Mode = "direct"
	// ModeProxy: di belakang reverse proxy (Nginx/HAProxy) — percaya X-Real-IP / X-Forwarded-For
	ModeProxy Mode = "proxy"
	// ModeCloudflare: di belakang Cloudflare — percaya CF-Connecting-IP
	ModeCloudflare Mode = "cloudflare"
)

// RealIP mengambil IP asli client berdasarkan proxy mode.
// Hasil selalu berupa IP bersih tanpa port.
//
// Urutan prioritas per mode:
//   - cloudflare: CF-Connecting-IP → X-Real-IP → X-Forwarded-For → RemoteAddr
//   - proxy:      X-Real-IP → X-Forwarded-For (first hop) → RemoteAddr
//   - direct:     RemoteAddr
func RealIP(r *http.Request, mode Mode) string {
	switch mode {
	case ModeCloudflare:
		if ip := cleanHeader(r.Header.Get("CF-Connecting-IP")); ip != "" {
			return ip
		}
		fallthrough
	case ModeProxy:
		if ip := cleanHeader(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// XFF bisa berisi chain: "client, proxy1, proxy2"
			// IP paling kiri adalah client asli
			parts := strings.SplitN(xff, ",", 2)
			if ip := cleanHeader(parts[0]); ip != "" {
				return ip
			}
		}
	}
	return stripPort(r.RemoteAddr)
}

// SourceLabel mengembalikan label sumber koneksi untuk keperluan logging.
// Nilai: "cloudflare" | "proxy" | "direct"
func SourceLabel(r *http.Request, mode Mode) string {
	switch mode {
	case ModeCloudflare:
		if r.Header.Get("CF-Connecting-IP") != "" {
			return "cloudflare"
		}
	case ModeProxy:
		if r.Header.Get("X-Real-IP") != "" || r.Header.Get("X-Forwarded-For") != "" {
			return "proxy"
		}
	}
	return "direct"
}

// cleanHeader membersihkan whitespace dan memvalidasi format IP.
// Mengembalikan "" jika bukan IP yang valid.
func cleanHeader(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if net.ParseIP(s) == nil {
		return ""
	}
	return s
}

// stripPort menghapus port dari "ip:port" atau "[ipv6]:port"
func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config adalah struktur konfigurasi aplikasi HAPM.
// Seluruh nilai diambil dari environment variable.
// Tidak ada file YAML — self-hosted friendly, Docker friendly.
type Config struct {
	App       AppConfig
	DB        DBConfig
	JWT       JWTConfig
	Security  SecurityConfig
	Log       LogConfig
	RateLimit RateLimitConfig
	Proxy     ProxyConfig
	CMC       CMCConfig
}

// AppConfig konfigurasi umum aplikasi
type AppConfig struct {
	Name    string
	Mode    string // development | production
	Port    int
	BaseURL string
}

// DBConfig konfigurasi database
type DBConfig struct {
	Driver string // sqlite | mariadb
	// SQLite
	Path string
	// MariaDB
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// JWTConfig konfigurasi JWT token
type JWTConfig struct {
	AccessSecret  string
	RefreshSecret string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
}

// SecurityConfig konfigurasi keamanan
type SecurityConfig struct {
	EncryptionKey string // 32-byte hex untuk AES-256-GCM
}

// LogConfig konfigurasi logging
type LogConfig struct {
	Level  string // debug | info | warn | error
	Format string // text | json
}

// RateLimitConfig konfigurasi rate limiting
type RateLimitConfig struct {
	LoginPerMinute     int
	LoginWindowMinutes int
	APIPerMinute       int
	LockoutAttempts    int
	LockoutDuration    time.Duration
}

// CMCConfig konfigurasi Certificate Management Center
type CMCConfig struct {
	// StoragePath: direktori root penyimpanan certificate files
	StoragePath string
	// WebRootPath: direktori webroot untuk HTTP-01 ACME challenge
	WebRootPath string
	// ACMEServiceURL: URL internal hapm-acme service
	ACMEServiceURL string
	// ChallengeAddr: alamat IP:port yang bisa diakses HAProxy node untuk HTTP-01 challenge
	// Contoh: "203.0.113.10:8282" (IP publik HAPM Controller)
	ChallengeAddr string
}

// ProxyConfig konfigurasi topologi proxy di depan aplikasi
type ProxyConfig struct {
	// Mode menentukan cara membaca IP asli client:
	//   direct     — tidak ada proxy, gunakan RemoteAddr
	//   proxy      — di belakang reverse proxy (Nginx/HAProxy), percaya X-Real-IP / X-Forwarded-For
	//   cloudflare — di belakang Cloudflare, percaya CF-Connecting-IP
	Mode string
}

var global *Config

// Load memuat konfigurasi dari environment variable.
// Wajib dipanggil sekali di awal aplikasi.
func Load() (*Config, error) {
	cfg := &Config{}

	// App
	cfg.App.Name = getEnv("APP_NAME", "HAProxy Manager")
	cfg.App.Mode = getEnv("APP_MODE", "production")
	cfg.App.BaseURL = getEnv("APP_BASE_URL", "http://localhost:8282")
	port, err := strconv.Atoi(getEnv("APP_PORT", "8282"))
	if err != nil {
		return nil, fmt.Errorf("[CONFIG] APP_PORT tidak valid: %v", err)
	}
	cfg.App.Port = port

	// Database
	cfg.DB.Driver = getEnv("APP_DB_DRIVER", "sqlite")
	cfg.DB.Path = detectDBPath()
	cfg.DB.DSN = getEnv("APP_DB_DSN", "")
	cfg.DB.MaxOpenConns = getEnvInt("APP_DB_MAX_OPEN_CONNS", 25)
	cfg.DB.MaxIdleConns = getEnvInt("APP_DB_MAX_IDLE_CONNS", 5)
	cfg.DB.ConnMaxLifetime = getEnvDuration("APP_DB_CONN_MAX_LIFETIME", 5*time.Minute)

	// JWT
	cfg.JWT.AccessSecret = getEnv("APP_JWT_ACCESS_SECRET", "")
	if cfg.JWT.AccessSecret == "" {
		return nil, fmt.Errorf("[CONFIG] APP_JWT_ACCESS_SECRET wajib diisi")
	}
	cfg.JWT.RefreshSecret = getEnv("APP_JWT_REFRESH_SECRET", "")
	if cfg.JWT.RefreshSecret == "" {
		return nil, fmt.Errorf("[CONFIG] APP_JWT_REFRESH_SECRET wajib diisi")
	}
	cfg.JWT.AccessExpiry = getEnvDuration("APP_JWT_ACCESS_EXPIRY", 15*time.Minute)
	cfg.JWT.RefreshExpiry = getEnvDuration("APP_JWT_REFRESH_EXPIRY", 7*24*time.Hour)

	// Security
	cfg.Security.EncryptionKey = getEnv("APP_ENCRYPTION_KEY", "")
	if cfg.Security.EncryptionKey == "" {
		return nil, fmt.Errorf("[CONFIG] APP_ENCRYPTION_KEY wajib diisi")
	}
	if len(cfg.Security.EncryptionKey) != 64 {
		return nil, fmt.Errorf("[CONFIG] APP_ENCRYPTION_KEY harus 64 hex characters (32 bytes)")
	}

	// Log
	cfg.Log.Level = strings.ToLower(getEnv("APP_LOG_LEVEL", "info"))
	cfg.Log.Format = strings.ToLower(getEnv("APP_LOG_FORMAT", "text"))

	// Rate Limit
	cfg.RateLimit.LoginPerMinute = getEnvInt("APP_RATE_LIMIT_LOGIN", 5)
	cfg.RateLimit.LoginWindowMinutes = getEnvInt("APP_RATE_LIMIT_LOGIN_WINDOW", 15)
	cfg.RateLimit.APIPerMinute = getEnvInt("APP_RATE_LIMIT_API", 100)
	cfg.RateLimit.LockoutAttempts = getEnvInt("APP_ACCOUNT_LOCKOUT_ATTEMPTS", 5)
	cfg.RateLimit.LockoutDuration = getEnvDuration("APP_ACCOUNT_LOCKOUT_DURATION", 15*time.Minute)

	// Proxy
	cfg.Proxy.Mode = strings.ToLower(getEnv("APP_PROXY_MODE", "direct"))
	if cfg.Proxy.Mode != "direct" && cfg.Proxy.Mode != "proxy" && cfg.Proxy.Mode != "cloudflare" {
		return nil, fmt.Errorf("[CONFIG] APP_PROXY_MODE tidak valid: harus 'direct', 'proxy', atau 'cloudflare'")
	}

	// CMC — Certificate Management Center
	base := dataDir()
	cfg.CMC.StoragePath = getEnv("CMC_STORAGE_PATH", base+"/storage/certificates")
	cfg.CMC.WebRootPath = getEnv("CMC_WEBROOT_PATH", base+"/acme-webroot")
	cfg.CMC.ACMEServiceURL = getEnv("CMC_ACME_SERVICE_URL", "http://hapm-acme:8889")
	cfg.CMC.ChallengeAddr = getEnv("CMC_CHALLENGE_ADDR", "")

	global = cfg
	return cfg, nil
}

// Get mengembalikan konfigurasi global.
// Panic jika Load() belum dipanggil.
func Get() *Config {
	if global == nil {
		panic("[CONFIG] Config belum di-load. Panggil config.Load() terlebih dahulu")
	}
	return global
}

// IsProduction mengembalikan true jika mode production
func (c *Config) IsProduction() bool {
	return c.App.Mode == "production"
}

// dataDir mengembalikan direktori data utama:
// /data (Docker volume) jika tersedia, atau ./data untuk lokal.
func dataDir() string {
	if _, err := os.Stat("/data"); err == nil {
		return "/data"
	}
	return "./data"
}

// detectDBPath menentukan path SQLite secara otomatis.
// Prioritas: APP_DB_PATH env → /data/hapm.db → ./data/hapm.db → ./hapm.db
func detectDBPath() string {
	if v := os.Getenv("APP_DB_PATH"); v != "" {
		return v
	}
	if _, err := os.Stat("/data"); err == nil {
		return "/data/hapm.db"
	}
	if _, err := os.Stat("./data"); err == nil {
		return "./data/hapm.db"
	}
	return "./hapm.db"
}

// ─── helpers ───────────────────────────────────────────────────────────────

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

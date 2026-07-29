package middleware

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/pkg/iputil"
)

// WAFEngine adalah engine WAF lengkap dengan in-memory cache.
// Urutan eksekusi: Whitelist → Blacklist → RateLimit → Rules → CORS (response)
type WAFEngine struct {
	cfg              *config.Config
	settingsSvc      domain.SettingsService
	blacklistRepo    domain.WAFBlacklistRepository
	whitelistRepo    domain.WAFWhitelistRepository
	rateLimitRepo    domain.WAFRateLimitRepository
	wafRuleRepo      domain.WAFRuleRepository
	corsRepo         domain.WAFCORSRepository

	// in-memory caches
	mu             sync.RWMutex
	blacklistCache []string // IP/CIDR entries
	whitelistCache []string
	corsCache      []*compiledCORSRule
	rlCache        []*domain.WAFRateLimit

	// rate limit tracking: map[profileID:ip] → *rlTracker
	rlMu      sync.RWMutex
	rlTracker map[string]*rlEntry

	cacheExpiry time.Time
}

type compiledCORSRule struct {
	rule   *domain.WAFCORSRule
	pathRE *regexp.Regexp
	origins []string // parsed from JSON
}

type rlEntry struct {
	mu          sync.Mutex
	hits        []time.Time
	blockedUntil time.Time
	violations  int // berapa kali exceed limit
}

func NewWAFEngine(
	cfg *config.Config,
	settingsSvc domain.SettingsService,
	blacklistRepo domain.WAFBlacklistRepository,
	whitelistRepo domain.WAFWhitelistRepository,
	rateLimitRepo domain.WAFRateLimitRepository,
	wafRuleRepo domain.WAFRuleRepository,
	corsRepo domain.WAFCORSRepository,
) *WAFEngine {
	e := &WAFEngine{
		cfg:           cfg,
		settingsSvc:   settingsSvc,
		blacklistRepo: blacklistRepo,
		whitelistRepo: whitelistRepo,
		rateLimitRepo: rateLimitRepo,
		wafRuleRepo:   wafRuleRepo,
		corsRepo:      corsRepo,
		rlTracker:     make(map[string]*rlEntry),
	}
	go e.backgroundRefresh()
	go e.backgroundCleanup()
	return e
}

// Middleware mengembalikan http.Handler yang menerapkan semua WAF layers.
func (e *WAFEngine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// WAF hanya aktif jika feature enabled
		enabled, _ := e.settingsSvc.IsWAFEnabled(ctx)
		if !enabled {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := iputil.RealIP(r, iputil.Mode(e.cfg.Proxy.Mode))

		// 1. Whitelist check — jika match, bypass semua WAF
		if e.isWhitelisted(clientIP) {
			e.injectCORS(w, r)
			next.ServeHTTP(w, r)
			return
		}

		// 2. Blacklist check
		if e.isBlacklisted(clientIP) {
			core.Error(w, http.StatusForbidden, "Akses ditolak: IP diblokir")
			return
		}

		// 3. Rate limiter
		if blocked, retryAfter := e.checkRateLimit(ctx, clientIP, r.URL.Path); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			core.TooManyRequests(w, "Terlalu banyak request, coba lagi dalam "+
				strconv.Itoa(retryAfter)+" detik")
			return
		}

		// 4. WAF rules (pattern matching)
		if blocked, reason := e.checkWAFRules(ctx, r, clientIP); blocked {
			core.Error(w, http.StatusForbidden, "Diblokir WAF: "+reason)
			return
		}

		// 5. Inject CORS ke response
		e.injectCORS(w, r)

		// Handle preflight OPTIONS
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ─── Whitelist ────────────────────────────────────────────────────────────────

func (e *WAFEngine) isWhitelisted(ip string) bool {
	e.ensureCache()
	e.mu.RLock()
	defer e.mu.RUnlock()

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}
	for _, entry := range e.whitelistCache {
		if matchIPOrCIDRStr(clientIP, entry) {
			return true
		}
	}
	return false
}

// ─── Blacklist ────────────────────────────────────────────────────────────────

func (e *WAFEngine) isBlacklisted(ip string) bool {
	e.ensureCache()
	e.mu.RLock()
	defer e.mu.RUnlock()

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}
	for _, entry := range e.blacklistCache {
		if matchIPOrCIDRStr(clientIP, entry) {
			return true
		}
	}
	return false
}

// AddToBlacklist menambah IP ke blacklist cache segera (tanpa tunggu refresh)
func (e *WAFEngine) AddToBlacklist(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blacklistCache = append(e.blacklistCache, ip)
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

func (e *WAFEngine) checkRateLimit(ctx context.Context, ip, path string) (blocked bool, retryAfter int) {
	e.ensureCache()
	e.mu.RLock()
	profiles := e.rlCache
	e.mu.RUnlock()

	for _, profile := range profiles {
		if !profile.Enabled {
			continue
		}
		re, err := regexp.Compile(profile.PathPattern)
		if err != nil || !re.MatchString(path) {
			continue
		}

		key := strconv.Itoa(profile.ID) + ":" + ip
		e.rlMu.RLock()
		entry, exists := e.rlTracker[key]
		e.rlMu.RUnlock()

		if !exists {
			e.rlMu.Lock()
			entry, exists = e.rlTracker[key]
			if !exists {
				entry = &rlEntry{}
				e.rlTracker[key] = entry
			}
			e.rlMu.Unlock()
		}

		entry.mu.Lock()
		// Cek apakah masih dalam periode blokir
		if time.Now().Before(entry.blockedUntil) {
			remaining := int(time.Until(entry.blockedUntil).Seconds()) + 1
			entry.mu.Unlock()
			return true, remaining
		}

		// Sliding window
		now := time.Now()
		cutoff := now.Add(-time.Duration(profile.WindowSeconds) * time.Second)
		valid := entry.hits[:0]
		for _, t := range entry.hits {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		valid = append(valid, now)
		entry.hits = valid

		if len(valid) > profile.MaxRequests {
			entry.blockedUntil = now.Add(time.Duration(profile.BlockDurationSeconds) * time.Second)
			entry.violations++

			// Auto-blacklist jika threshold tercapai
			if profile.AutoBlacklistThreshold != nil && entry.violations >= *profile.AutoBlacklistThreshold {
				go func() {
					expiry := time.Now().Add(24 * time.Hour)
					_ = e.blacklistRepo.Create(context.Background(), &domain.WAFBlacklist{
						IPAddress: ip,
						Reason:    "Auto-blacklisted: rate limit exceeded repeatedly",
						ExpiresAt: &expiry,
					})
					e.AddToBlacklist(ip)
				}()
			}

			retryAfter := profile.BlockDurationSeconds
			entry.mu.Unlock()
			return true, retryAfter
		}
		entry.mu.Unlock()
	}
	return false, 0
}

// ─── WAF Rules ────────────────────────────────────────────────────────────────

func (e *WAFEngine) checkWAFRules(ctx context.Context, r *http.Request, clientIP string) (bool, string) {
	rules, err := e.wafRuleRepo.List(ctx)
	if err != nil || len(rules) == 0 {
		return false, ""
	}

	parsedIP := net.ParseIP(clientIP)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.Action != "deny" {
			continue
		}

		matched := false
		switch rule.RuleType {
		case "ip_block":
			if parsedIP != nil {
				matched = matchIPOrCIDRStr(parsedIP, rule.Value)
			}
		case "path_block":
			if re, err := regexp.Compile(rule.Value); err == nil {
				matched = re.MatchString(r.URL.Path)
			}
		case "ua_block":
			matched = strings.Contains(
				strings.ToLower(r.UserAgent()),
				strings.ToLower(rule.Value),
			)
		case "header_block":
			// format: "Header-Name: value"
			parts := strings.SplitN(rule.Value, ":", 2)
			if len(parts) == 2 {
				matched = strings.Contains(
					strings.ToLower(r.Header.Get(strings.TrimSpace(parts[0]))),
					strings.ToLower(strings.TrimSpace(parts[1])),
				)
			}
		}

		if matched {
			return true, rule.Name + " (" + rule.RuleType + ")"
		}
	}
	return false, ""
}

// ─── CORS ─────────────────────────────────────────────────────────────────────

func (e *WAFEngine) injectCORS(w http.ResponseWriter, r *http.Request) {
	// Skip jika request dari Cloudflare (mereka handle CORS sendiri)
	if r.Header.Get("CF-Ray") != "" {
		return
	}

	e.ensureCache()
	e.mu.RLock()
	rules := e.corsCache
	e.mu.RUnlock()

	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}

	for _, cr := range rules {
		if !cr.rule.Enabled {
			continue
		}
		if !cr.pathRE.MatchString(r.URL.Path) {
			continue
		}

		// Match origin
		allowedOrigin := matchOrigin(origin, cr.origins)
		if allowedOrigin == "" {
			continue
		}

		// Security: jangan gunakan wildcard jika credentials=true
		if cr.rule.AllowCredentials && allowedOrigin == "*" {
			allowedOrigin = origin
		}

		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", cr.rule.AllowedMethods)
		w.Header().Set("Access-Control-Allow-Headers", cr.rule.AllowedHeaders)
		if cr.rule.ExposeHeaders != "" {
			w.Header().Set("Access-Control-Expose-Headers", cr.rule.ExposeHeaders)
		}
		if cr.rule.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(cr.rule.MaxAgeSeconds))
		w.Header().Set("Vary", "Origin")
		return
	}
}

// ─── Cache management ─────────────────────────────────────────────────────────

func (e *WAFEngine) ensureCache() {
	e.mu.RLock()
	fresh := time.Now().Before(e.cacheExpiry)
	e.mu.RUnlock()
	if fresh {
		return
	}
	e.refreshCache()
}

func (e *WAFEngine) refreshCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Blacklist
	blRows, _ := e.blacklistRepo.List(ctx)
	blCache := make([]string, 0, len(blRows))
	now := time.Now()
	for _, bl := range blRows {
		if bl.ExpiresAt == nil || bl.ExpiresAt.After(now) {
			blCache = append(blCache, bl.IPAddress)
		}
	}

	// Whitelist — filter entri yang sudah kadaluarsa
	wlRows, _ := e.whitelistRepo.List(ctx)
	wlCache := make([]string, 0, len(wlRows))
	for _, wl := range wlRows {
		if wl.ExpiresAt == nil || wl.ExpiresAt.After(now) {
			wlCache = append(wlCache, wl.IPAddress)
		}
	}

	// Rate limits
	rlRows, _ := e.rateLimitRepo.ListEnabled(ctx)

	// CORS
	corsRows, _ := e.corsRepo.ListEnabled(ctx)
	corsCache := make([]*compiledCORSRule, 0, len(corsRows))
	for _, rule := range corsRows {
		re, err := regexp.Compile(rule.PathPattern)
		if err != nil {
			continue
		}
		origins := parseOrigins(rule.AllowedOrigins)
		corsCache = append(corsCache, &compiledCORSRule{
			rule:    rule,
			pathRE:  re,
			origins: origins,
		})
	}

	e.mu.Lock()
	e.blacklistCache = blCache
	e.whitelistCache = wlCache
	e.rlCache = rlRows
	e.corsCache = corsCache
	e.cacheExpiry = time.Now().Add(time.Minute)
	e.mu.Unlock()
}

func (e *WAFEngine) backgroundRefresh() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		e.refreshCache()
	}
}

func (e *WAFEngine) backgroundCleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		// Hapus expired tracking entries
		e.rlMu.Lock()
		cutoff := time.Now().Add(-time.Hour)
		for key, entry := range e.rlTracker {
			entry.mu.Lock()
			if len(entry.hits) == 0 || (entry.blockedUntil.Before(cutoff) &&
				(len(entry.hits) == 0 || entry.hits[len(entry.hits)-1].Before(cutoff))) {
				delete(e.rlTracker, key)
			}
			entry.mu.Unlock()
		}
		e.rlMu.Unlock()

		// Hapus expired blacklist dari DB
		_ = e.blacklistRepo.CleanExpired(context.Background())
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func matchIPOrCIDRStr(clientIP net.IP, entry string) bool {
	if _, ipNet, err := net.ParseCIDR(entry); err == nil {
		return ipNet.Contains(clientIP)
	}
	if entryIP := net.ParseIP(entry); entryIP != nil {
		return clientIP.Equal(entryIP)
	}
	return false
}

func parseOrigins(raw string) []string {
	var origins []string
	if err := json.Unmarshal([]byte(raw), &origins); err != nil {
		// fallback: treat as single origin
		origins = []string{raw}
	}
	return origins
}

func matchOrigin(origin string, allowed []string) string {
	for _, a := range allowed {
		if a == "*" {
			return "*"
		}
		if a == origin {
			return origin
		}
		// Wildcard subdomain: https://*.example.com
		if strings.HasPrefix(a, "https://*.") || strings.HasPrefix(a, "http://*.") {
			schema := a[:strings.Index(a, "*")]
			domain := a[strings.Index(a, "*")+1:]
			if strings.HasPrefix(origin, schema) && strings.HasSuffix(origin, domain) {
				return origin
			}
		}
	}
	return ""
}

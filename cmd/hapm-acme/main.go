// hapm-acme adalah ACME worker service untuk HAPM Certificate Management Center.
//
// Service ini berjalan sebagai container Docker terpisah dan bertugas:
//   - Menjalankan LEGO CLI untuk issue/renew/revoke certificate
//   - Menyimpan hasil ke shared volume (/data)
//   - Melayani HTTP-01 ACME challenge (webroot mode)
//
// hapm berkomunikasi dengan hapm-acme melalui internal Docker Network.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// legoConfig menyimpan opsi runtime LEGO CLI yang dibaca dari env.
type legoConfig struct {
	dnsDisableCP     bool   // LEGO_DNS_DISABLE_CP=true → --dns.disable-cp
	dnsResolvers     string // LEGO_DNS_RESOLVERS=8.8.8.8:53,1.1.1.1:53 → --dns.resolvers VALUE
	execProviderPath string // CF_EXEC_PROVIDER_PATH → path ke cf-dns-provider.sh
	maxRetries       int    // LEGO_RETRY_MAX — max retry saat DNS propagation gagal (default 1)
	retryWait        int    // LEGO_RETRY_WAIT — detik tunggu antar retry (default 30)
}

// IssueRequest dari hapm
type IssueRequest struct {
	JobUUID     string   `json:"job_uuid"`
	CertUUID    string   `json:"cert_uuid"`
	Domains     []string `json:"domains"`
	Challenge   string   `json:"challenge"`
	CFToken     string   `json:"cf_token,omitempty"`
	Email       string   `json:"email"`
	Staging     bool     `json:"staging"`
	StoragePath string   `json:"storage_path"`
	WebRootPath string   `json:"webroot_path"`
}

// RenewRequest dari hapm
type RenewRequest struct {
	JobUUID     string   `json:"job_uuid"`
	CertUUID    string   `json:"cert_uuid"`
	Domains     []string `json:"domains"`
	Challenge   string   `json:"challenge"`
	CFToken     string   `json:"cf_token,omitempty"`
	Email       string   `json:"email"`
	Staging     bool     `json:"staging"`
	StoragePath string   `json:"storage_path"`
	WebRootPath string   `json:"webroot_path"`
}

// RevokeRequest dari hapm
type RevokeRequest struct {
	JobUUID     string `json:"job_uuid"`
	CertUUID    string `json:"cert_uuid"`
	Domain      string `json:"domain"`
	Email       string `json:"email"`
	Staging     bool   `json:"staging"`
	StoragePath string `json:"storage_path"`
}

// ACMEResponse ke hapm
type ACMEResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Logs    string `json:"logs,omitempty"`
}

func main() {
	port := getEnv("ACME_PORT", "8889")
	legoPath := resolveLegoBin()

	cfg := legoConfig{
		dnsDisableCP:     os.Getenv("LEGO_DNS_DISABLE_CP") == "true",
		dnsResolvers:     os.Getenv("LEGO_DNS_RESOLVERS"),
		execProviderPath: resolveExecProvider(),
		maxRetries:       envInt("LEGO_RETRY_MAX", 1),
		retryWait:        envInt("LEGO_RETRY_WAIT", 30),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/internal/health", handleHealth)
	mux.HandleFunc("/internal/issue", makeIssueHandler(legoPath, cfg))
	mux.HandleFunc("/internal/renew", makeRenewHandler(legoPath, cfg))
	mux.HandleFunc("/internal/revoke", makeRevokeHandler(legoPath, cfg))

	addr := ":" + port
	log.Printf("[hapm-acme] Service berjalan di %s (LEGO: %s, dns.disable-cp: %v)", addr, legoPath, cfg.dnsDisableCP)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[hapm-acme] Fatal: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func makeIssueHandler(legoPath string, cfg legoConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req IssueRequest
		if err := decodeBody(r, &req); err != nil {
			writeError(w, err.Error())
			return
		}

		log.Printf("[hapm-acme] Issue: job=%s cert=%s domains=%v", req.JobUUID, req.CertUUID, req.Domains)

		if err := os.MkdirAll(req.StoragePath, 0700); err != nil {
			writeError(w, fmt.Sprintf("buat direktori storage gagal: %v", err))
			return
		}
		if req.WebRootPath != "" {
			_ = os.MkdirAll(filepath.Join(req.WebRootPath, ".well-known", "acme-challenge"), 0755)
		}

		var logs string
		var err error

		if req.Challenge == "dns01" {
			// Gunakan implementasi native Go — menghindari masalah lego CLI exec provider
			// dan firewall yang memblokir UDP ke Cloudflare authoritative NS.
			logs, err = issueCertNative(&req, cfg)
			if err != nil {
				writeErrorWithLogs(w, fmt.Sprintf("Issue gagal: %v", err), logs)
				return
			}
		} else {
			args := buildLegoArgs(req.Email, req.Domains, req.Challenge, req.StoragePath, req.WebRootPath, req.Staging, cfg)
			args = append(args, "run")
			for attempt := 0; attempt <= cfg.maxRetries; attempt++ {
				if attempt > 0 {
					log.Printf("[hapm-acme] Issue retry %d/%d: menunggu %ds...", attempt, cfg.maxRetries, cfg.retryWait)
					time.Sleep(time.Duration(cfg.retryWait) * time.Second)
				}
				logs, err = runLego(legoPath, req.CFToken, args, 10*time.Minute, cfg)
				if err == nil || !isRetriableLegoError(logs) {
					break
				}
				log.Printf("[hapm-acme] Issue attempt %d gagal: %v", attempt+1, err)
			}
			if err != nil {
				writeErrorWithLogs(w, fmt.Sprintf("LEGO issue gagal: %v", err), logs)
				return
			}
		}

		writeSuccess(w, "Certificate berhasil diterbitkan", logs)
	}
}

func makeRenewHandler(legoPath string, cfg legoConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req RenewRequest
		if err := decodeBody(r, &req); err != nil {
			writeError(w, err.Error())
			return
		}

		log.Printf("[hapm-acme] Renew: job=%s cert=%s", req.JobUUID, req.CertUUID)

		var logs string
		var err error

		if req.Challenge == "dns01" {
			logs, err = renewCertNative(&req, cfg)
			if err != nil {
				writeErrorWithLogs(w, fmt.Sprintf("Renew gagal: %v", err), logs)
				return
			}
		} else {
			args := buildLegoArgs(req.Email, req.Domains, req.Challenge, req.StoragePath, req.WebRootPath, req.Staging, cfg)
			args = append(args, "renew", "--renew-hook", "echo renewed")
			for attempt := 0; attempt <= cfg.maxRetries; attempt++ {
				if attempt > 0 {
					log.Printf("[hapm-acme] Renew retry %d/%d: menunggu %ds...", attempt, cfg.maxRetries, cfg.retryWait)
					time.Sleep(time.Duration(cfg.retryWait) * time.Second)
				}
				logs, err = runLego(legoPath, req.CFToken, args, 10*time.Minute, cfg)
				if err == nil || !isRetriableLegoError(logs) {
					break
				}
				log.Printf("[hapm-acme] Renew attempt %d gagal: %v", attempt+1, err)
			}
			if err != nil {
				writeErrorWithLogs(w, fmt.Sprintf("LEGO renew gagal: %v", err), logs)
				return
			}
		}

		writeSuccess(w, "Certificate berhasil diperpanjang", logs)
	}
}

func makeRevokeHandler(legoPath string, cfg legoConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req RevokeRequest
		if err := decodeBody(r, &req); err != nil {
			writeError(w, err.Error())
			return
		}

		log.Printf("[hapm-acme] Revoke: cert=%s domain=%s", req.CertUUID, req.Domain)

		args := []string{
			"--email", req.Email,
			"--path", req.StoragePath,
		}
		if req.Staging {
			args = append(args, "--server", "https://acme-staging-v02.api.letsencrypt.org/directory")
		}
		if cfg.dnsResolvers != "" {
			args = append(args, "--dns.resolvers", cfg.dnsResolvers)
		}
		args = append(args, "revoke")

		logs, err := runLego(legoPath, "", args, 2*time.Minute, cfg)
		if err != nil {
			writeErrorWithLogs(w, fmt.Sprintf("LEGO revoke gagal: %v", err), logs)
			return
		}

		writeSuccess(w, "Certificate berhasil direvoke", logs)
	}
}

// buildLegoArgs membangun argumen dasar LEGO CLI
func buildLegoArgs(email string, domains []string, challenge, storagePath, webRootPath string, staging bool, cfg legoConfig) []string {
	args := []string{
		"--email", email,
		"--path", storagePath,
		"--accept-tos",
	}

	if staging {
		args = append(args, "--server", "https://acme-staging-v02.api.letsencrypt.org/directory")
	}

	for _, d := range domains {
		args = append(args, "--domains", d)
	}

	switch challenge {
	case "dns01":
		if cfg.execProviderPath != "" {
			// Gunakan exec provider: script menangani propagasi via Cloudflare DoH (HTTPS),
			// menghindari firewall yang memblokir UDP langsung ke Cloudflare authoritative NS.
			args = append(args, "--dns", "exec", "--dns.disable-cp")
		} else {
			args = append(args, "--dns", "cloudflare")
			if cfg.dnsDisableCP {
				args = append(args, "--dns.disable-cp")
			}
			if cfg.dnsResolvers != "" {
				args = append(args, "--dns.resolvers", cfg.dnsResolvers)
			}
		}
	case "http01":
		if webRootPath != "" {
			args = append(args, "--http", "--http.webroot", webRootPath)
		} else {
			args = append(args, "--http", "--http.port", ":8888")
		}
	}

	return args
}

// runLego menjalankan perintah LEGO CLI dan mengembalikan output log
func runLego(legoPath, cfToken string, args []string, timeout time.Duration, cfg legoConfig) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, legoPath, args...)

	// Set environment variables
	env := os.Environ()
	if cfToken != "" {
		env = append(env, "CF_DNS_API_TOKEN="+cfToken)
	}
	if cfg.execProviderPath != "" {
		env = append(env, "EXEC_PATH="+cfg.execProviderPath)
	}
	cmd.Env = env

	var sb strings.Builder
	cmd.Stdout = io.MultiWriter(os.Stdout, &sb)
	cmd.Stderr = io.MultiWriter(os.Stderr, &sb)

	if err := cmd.Run(); err != nil {
		return sb.String(), err
	}
	return sb.String(), nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func decodeBody(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func writeSuccess(w http.ResponseWriter, msg, logs string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ACMEResponse{Success: true, Message: msg, Logs: logs})
}

func writeError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(ACMEResponse{Success: false, Message: msg})
}

func writeErrorWithLogs(w http.ResponseWriter, msg, logs string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(ACMEResponse{Success: false, Message: msg, Logs: logs})
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return fallback
}

// isRetriableLegoError menentukan apakah error dari lego layak di-retry.
// Retry masuk akal untuk masalah DNS propagation transient, bukan error konfigurasi.
func isRetriableLegoError(logs string) bool {
	return strings.Contains(logs, "No TXT record found") ||
		strings.Contains(logs, "propagation: time limit exceeded") ||
		strings.Contains(logs, "i/o timeout")
}

// resolveExecProvider mencari path script cf-dns-provider.sh:
// 1. Env CF_EXEC_PROVIDER_PATH
// 2. ./scripts/cf-dns-provider.sh (relatif ke working dir)
// 3. Direktori yang sama dengan executable hapm-acme
func resolveExecProvider() string {
	if p := os.Getenv("CF_EXEC_PROVIDER_PATH"); p != "" {
		return p
	}
	if _, err := os.Stat("./scripts/cf-dns-provider.sh"); err == nil {
		abs, _ := filepath.Abs("./scripts/cf-dns-provider.sh")
		return abs
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "scripts", "cf-dns-provider.sh")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// resolveLegoBin mencari binary lego dengan urutan prioritas:
// 1. Env LEGO_PATH (eksplisit dari .env atau make dev)
// 2. Lookup lego di PATH (menangani Homebrew Apple Silicon /opt/homebrew/bin)
// 3. Fallback hardcoded /usr/local/bin/lego (Homebrew Intel Mac / Linux)
func resolveLegoBin() string {
	if p := os.Getenv("LEGO_PATH"); p != "" {
		return p
	}
	if p, err := exec.LookPath("lego"); err == nil {
		return p
	}
	return "/usr/local/bin/lego"
}

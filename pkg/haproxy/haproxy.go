// Package haproxy menyediakan tools untuk generate, validasi, dan deployment
// konfigurasi HAProxy ke node yang dikelola HAPM.
package haproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/pkg/ssh"
)

// Generator mendefinisikan kontrak untuk generate konfigurasi HAProxy
type Generator interface {
	// Generate menghasilkan (haproxy.cfg content, hosts.map content, error)
	Generate(ctx context.Context, node *domain.Node, domains []*domain.DomainEntry, pools []*domain.BackendPool, certs []*domain.Certificate, services []*domain.Service, authGroups []*domain.AuthGroup) (string, string, error)
}

// Validator mendefinisikan kontrak untuk validasi konfigurasi HAProxy
type Validator interface {
	Validate(ctx context.Context, conn *ssh.Connection, configContent string) (bool, string, error)
}

// StatsCollector mendefinisikan kontrak untuk mengambil statistik HAProxy
type StatsCollector interface {
	GetStats(ctx context.Context, conn *ssh.Connection) (*domain.NodeStats, error)
	GetFrontendStats(ctx context.Context, conn *ssh.Connection) ([]*domain.FrontendStats, error)
	GetBackendStats(ctx context.Context, conn *ssh.Connection) ([]*domain.BackendStats, error)
}

// Provisioner mendefinisikan kontrak untuk provisioning HAProxy pada node baru
type Provisioner interface {
	Install(ctx context.Context, conn *ssh.Connection) error
	GetVersion(ctx context.Context, conn *ssh.Connection) (string, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// GENERATOR IMPLEMENTATION
// ─────────────────────────────────────────────────────────────────────────────

// generator implements Generator
type generator struct{}

// NewGenerator membuat instance Generator baru
func NewGenerator() Generator {
	return &generator{}
}

// Generate menghasilkan konfigurasi HAProxy 3.x dari domain entries, backend pools, SSL certs, services, dan auth groups.
// Mengembalikan (haproxy.cfg content, hosts.map content, error).
// hosts.map di-deploy ke /etc/haproxy/map/hosts di node untuk routing domain via map file.
func (g *generator) Generate(
	ctx context.Context,
	node *domain.Node,
	domains []*domain.DomainEntry,
	pools []*domain.BackendPool,
	certs []*domain.Certificate,
	services []*domain.Service,
	authGroups []*domain.AuthGroup,
) (string, string, error) {
	var sb strings.Builder
	var hm strings.Builder // content untuk /etc/haproxy/map/hosts

	// ── global section ──
	sb.WriteString("global\n")
	sb.WriteString("    log /dev/log local0\n")
	sb.WriteString("    log /dev/log local1 notice\n")
	sb.WriteString("    chroot /var/lib/haproxy\n")
	sb.WriteString("    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners\n")
	sb.WriteString("    stats timeout 30s\n")
	sb.WriteString("    user haproxy\n")
	sb.WriteString("    group haproxy\n")
	sb.WriteString("    daemon\n")
	sb.WriteString("    maxconn 50000\n")
	// HAProxy 3.x: ssl-dh-param-file menggantikan tune.ssl.default-dh-param
	sb.WriteString("    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\n")
	sb.WriteString("    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n")
	sb.WriteString("    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets\n\n")

	// ── defaults section ──
	sb.WriteString("defaults\n")
	sb.WriteString("    log global\n")
	sb.WriteString("    mode http\n")
	sb.WriteString("    option httplog\n")
	sb.WriteString("    option dontlognull\n")
	sb.WriteString("    option forwardfor\n")
	sb.WriteString("    option http-server-close\n")
	sb.WriteString("    option redispatch\n")
	sb.WriteString("    retries 3\n")
	sb.WriteString("    timeout connect   5s\n")
	sb.WriteString("    timeout client   50s\n")
	sb.WriteString("    timeout server   50s\n")
	sb.WriteString("    timeout tunnel 3600s\n\n")

	// ── userlist blocks (HAProxy Basic Auth) ──
	// Satu userlist per group yang enabled dan memiliki member.
	// Diletakkan sebelum frontend agar bisa direferensikan dari http-request auth.
	groupUserlistName := make(map[int]string, len(authGroups)) // groupID → sanitized userlist name
	for _, ag := range authGroups {
		if !ag.Enabled || len(ag.Members) == 0 {
			continue
		}
		ulName := sanitizeName(ag.GroupName) + "_users"
		groupUserlistName[ag.ID] = ulName
		sb.WriteString(fmt.Sprintf("userlist %s\n", ulName))
		for _, u := range ag.Members {
			if u.Enabled && u.PasswordHash != "" {
				sb.WriteString(fmt.Sprintf("    user %s password %s\n", u.Username, u.PasswordHash))
			}
		}
		sb.WriteString("\n")
	}

	// Deteksi apakah ada domain SSL terminate atau passthrough
	hasSSLTerminate := false
	hasSSLPassthrough := false
	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		if d.SSLMode == domain.SSLModeTerminate {
			hasSSLTerminate = true
		}
		if d.SSLMode == domain.SSLModePassthrough {
			hasSSLPassthrough = true
		}
	}

	// ── Build hosts.map ──
	// Semua domain non-passthrough masuk map file; routing HTTP & HTTPS frontend pakai map()
	// sehingga frontend config tidak membengkak seiring bertambahnya domain.
	hm.WriteString("# Generated by HAPM — do not edit manually\n")
	for _, d := range domains {
		if !d.Enabled || d.SSLMode == domain.SSLModePassthrough {
			continue
		}
		fmt.Fprintf(&hm, "%s backend_%s\n", strings.ToLower(d.DomainName), sanitizeName(d.DomainName))
	}

	// ── ACME challenge backend (HTTP-01) ──
	// Selalu ada agar acme.sh HTTP-01 bisa berjalan tanpa mengganggu traffic
	sb.WriteString("backend acme_challenge\n")
	sb.WriteString("    mode http\n")
	sb.WriteString("    server acme_local 127.0.0.1:8888\n\n")

	// ── HTTP frontend (port 80) ──
	// Urutan HAProxy yang benar: acl → http-request → use_backend
	sb.WriteString("frontend http_in\n")
	sb.WriteString("    bind *:80\n")
	sb.WriteString("    mode http\n")
	sb.WriteString("    acl is_acme_challenge path_beg /.well-known/acme-challenge/\n")

	// ACL per-domain untuk redirect dan auth
	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		if d.SSLMode == domain.SSLModeTerminate && d.HTTPRedirect {
			aclName := "host_redir_" + sanitizeName(d.DomainName)
			sb.WriteString(fmt.Sprintf("    acl %s hdr(host) -i %s\n", aclName, d.DomainName))
		}
		if d.AuthGroupID != nil && d.SSLMode != domain.SSLModePassthrough {
			if _, ok := groupUserlistName[*d.AuthGroupID]; ok {
				aclName := "host_auth_" + sanitizeName(d.DomainName)
				sb.WriteString(fmt.Sprintf("    acl %s hdr(host) -i %s\n", aclName, d.DomainName))
			}
		}
	}

	// Cloudflare real IP extraction
	if node.BehindCloudflare {
		sb.WriteString("    http-request set-header X-Real-IP %[req.hdr(CF-Connecting-IP)] if { req.hdr(CF-Connecting-IP) -m found }\n")
	}

	// Redirect HTTP→HTTPS per-domain
	for _, d := range domains {
		if !d.Enabled || d.SSLMode != domain.SSLModeTerminate || !d.HTTPRedirect {
			continue
		}
		aclName := "host_redir_" + sanitizeName(d.DomainName)
		sb.WriteString(fmt.Sprintf("    http-request redirect scheme https code 301 if %s !is_acme_challenge\n", aclName))
	}

	// Basic Auth per-domain
	for _, d := range domains {
		if !d.Enabled || d.AuthGroupID == nil || d.SSLMode == domain.SSLModePassthrough {
			continue
		}
		ulName, ok := groupUserlistName[*d.AuthGroupID]
		if !ok {
			continue
		}
		aclName := "host_auth_" + sanitizeName(d.DomainName)
		realm := sanitizeName(d.DomainName)
		sb.WriteString(fmt.Sprintf("    http-request auth realm %s if %s !{ http_auth(%s) }\n", realm, aclName, ulName))
	}

	// use_backend setelah semua http-request rules (urutan benar untuk HAProxy)
	sb.WriteString("    use_backend acme_challenge if is_acme_challenge\n")
	sb.WriteString("    use_backend %[req.hdr(host),lower,map(/etc/haproxy/map/hosts)] if !is_acme_challenge\n")
	sb.WriteString("\n")

	// ── HTTPS frontend (port 443, SSL terminate) ──
	// Aktif jika: ada domain ssl_mode=terminate ATAU https_frontend_enabled=true pada node
	if hasSSLTerminate || node.HTTPSFrontendEnabled {
		sb.WriteString("frontend https_in\n")
		// Semua cert dari /etc/haproxy/certs/ — HAProxy 3.x mendukung direktori
		sb.WriteString("    bind *:443 ssl crt /etc/haproxy/certs/ alpn h2,http/1.1\n")
		sb.WriteString("    mode http\n")
		sb.WriteString("    option forwardfor\n")
		sb.WriteString("    http-request set-header X-Forwarded-Proto https\n")
		// HSTS — hanya dikirim dari HTTPS frontend
		sb.WriteString("    http-response set-header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"\n")

		if node.BehindCloudflare {
			sb.WriteString("    # Ekstrak real client IP dari header Cloudflare\n")
			sb.WriteString("    http-request set-header X-Real-IP %[req.hdr(CF-Connecting-IP)] if { req.hdr(CF-Connecting-IP) -m found }\n")
		}

		// Basic Auth per-domain pada HTTPS frontend
		for _, d := range domains {
			if !d.Enabled || d.SSLMode != domain.SSLModeTerminate || d.AuthGroupID == nil {
				continue
			}
			ulName, ok := groupUserlistName[*d.AuthGroupID]
			if !ok {
				continue
			}
			aclName := "host_auth_" + sanitizeName(d.DomainName)
			realm := sanitizeName(d.DomainName)
			sb.WriteString(fmt.Sprintf("    acl %s hdr(host) -i %s\n", aclName, d.DomainName))
			sb.WriteString(fmt.Sprintf("    http-request auth realm %s if %s !{ http_auth(%s) }\n", realm, aclName, ulName))
		}

		// Routing via hosts.map — satu directive untuk semua domain SSL terminate
		sb.WriteString("    use_backend %[req.hdr(host),lower,map(/etc/haproxy/map/hosts)]\n")
		sb.WriteString("\n")
	}

	// ── TCP frontend (port 443, SSL passthrough) ──
	if hasSSLPassthrough {
		sb.WriteString("frontend tcp_ssl_passthrough\n")
		sb.WriteString("    bind *:8443\n") // port berbeda agar tidak konflik dengan terminate
		sb.WriteString("    mode tcp\n")
		sb.WriteString("    option tcplog\n")

		for _, d := range domains {
			if !d.Enabled || d.SSLMode != domain.SSLModePassthrough {
				continue
			}
			name := sanitizeName(d.DomainName)
			sb.WriteString(fmt.Sprintf("    use_backend backend_tcp_%s\n", name))
		}
		sb.WriteString("\n")
	}

	// ── backends HTTP/HTTPS ──
	poolMap := make(map[int]*domain.BackendPool, len(pools))
	for _, p := range pools {
		poolMap[p.ID] = p
	}

	usedPools := make(map[int]bool)
	for _, d := range domains {
		if d.Enabled {
			usedPools[d.BackendPoolID] = true
		}
	}
	// Pool yang digunakan oleh service listen block tidak perlu dirender sebagai standalone backend
	for _, svc := range services {
		if svc.Enabled {
			usedPools[svc.BackendPoolID] = true
		}
	}

	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		pool, ok := poolMap[d.BackendPoolID]
		if !ok {
			continue
		}

		name := sanitizeName(d.DomainName)

		if d.SSLMode == domain.SSLModePassthrough {
			// TCP backend untuk passthrough
			sb.WriteString(fmt.Sprintf("backend backend_tcp_%s\n", name))
			sb.WriteString("    mode tcp\n")
			sb.WriteString(fmt.Sprintf("    balance %s\n", pool.Algorithm))
			writeHealthCheckOptions(&sb, pool.HealthCheckConf)
			writeServerList(&sb, pool, false)
			sb.WriteString("\n")
			continue
		}

		sb.WriteString(fmt.Sprintf("backend backend_%s\n", name))
		if pool.Protocol == domain.BackendProtocolTCP {
			sb.WriteString("    mode tcp\n")
		} else {
			sb.WriteString("    mode http\n")
		}
		sb.WriteString(fmt.Sprintf("    balance %s\n", pool.Algorithm))
		sb.WriteString(fmt.Sprintf("    timeout connect %dms\n", pool.TimeoutConnect))
		sb.WriteString(fmt.Sprintf("    timeout server  %dms\n", pool.TimeoutServer))
		writeForwardHeaders(&sb, pool)
		writeHealthCheckOptions(&sb, pool.HealthCheckConf)
		writeServerList(&sb, pool, true)
		sb.WriteString("\n")
	}

	// Standalone backends (pool tanpa domain maupun service)
	for _, pool := range pools {
		if usedPools[pool.ID] {
			continue
		}
		sb.WriteString(fmt.Sprintf("backend pool_%s\n", sanitizeName(pool.Name)))
		// Mode: protocol tcp → tcp; http/https → http; fallback ke health check type
		if pool.Protocol == domain.BackendProtocolTCP || isTCPHealthCheck(pool.HealthCheckConf.Type) {
			sb.WriteString("    mode tcp\n")
		} else {
			sb.WriteString("    mode http\n")
		}
		sb.WriteString(fmt.Sprintf("    balance %s\n", pool.Algorithm))
		writeForwardHeaders(&sb, pool)
		writeHealthCheckOptions(&sb, pool.HealthCheckConf)
		writeServerList(&sb, pool, true)
		sb.WriteString("\n")
	}

	// ── TCP/HTTP/HTTPS service listen blocks ─────────────────────────────────
	// Setiap service menghasilkan satu `listen` block tersendiri di HAProxy.
	for _, svc := range services {
		if !svc.Enabled {
			continue
		}
		pool, ok := poolMap[svc.BackendPoolID]
		if !ok {
			continue
		}

		name := sanitizeName(svc.Name)

		switch svc.ServiceType {
		case domain.ServiceTypeTCP:
			sb.WriteString(fmt.Sprintf("listen %s\n", name))
			sb.WriteString(fmt.Sprintf("    bind *:%d\n", svc.ListenPort))
			sb.WriteString("    mode tcp\n")
			sb.WriteString("    option tcplog\n")
			sb.WriteString(fmt.Sprintf("    balance %s\n", pool.Algorithm))
			sb.WriteString(fmt.Sprintf("    timeout connect %dms\n", pool.TimeoutConnect))
			sb.WriteString(fmt.Sprintf("    timeout client  %dms\n", pool.TimeoutServer))
			sb.WriteString(fmt.Sprintf("    timeout server  %dms\n", pool.TimeoutServer))
			writeHealthCheckOptions(&sb, pool.HealthCheckConf)
			writeServerList(&sb, pool, false)
			sb.WriteString("\n")

		case domain.ServiceTypeHTTPS:
			sb.WriteString(fmt.Sprintf("listen %s\n", name))
			sb.WriteString(fmt.Sprintf("    bind *:%d ssl crt /etc/haproxy/certs/ alpn h2,http/1.1\n", svc.ListenPort))
			sb.WriteString("    mode http\n")
			sb.WriteString(fmt.Sprintf("    balance %s\n", pool.Algorithm))
			sb.WriteString(fmt.Sprintf("    timeout connect %dms\n", pool.TimeoutConnect))
			sb.WriteString(fmt.Sprintf("    timeout server  %dms\n", pool.TimeoutServer))
			writeForwardHeaders(&sb, pool)
			writeHealthCheckOptions(&sb, pool.HealthCheckConf)
			writeServerList(&sb, pool, true)
			sb.WriteString("\n")

		default: // ServiceTypeHTTP
			sb.WriteString(fmt.Sprintf("listen %s\n", name))
			sb.WriteString(fmt.Sprintf("    bind *:%d\n", svc.ListenPort))
			sb.WriteString("    mode http\n")
			sb.WriteString(fmt.Sprintf("    balance %s\n", pool.Algorithm))
			sb.WriteString(fmt.Sprintf("    timeout connect %dms\n", pool.TimeoutConnect))
			sb.WriteString(fmt.Sprintf("    timeout server  %dms\n", pool.TimeoutServer))
			writeForwardHeaders(&sb, pool)
			writeHealthCheckOptions(&sb, pool.HealthCheckConf)
			writeServerList(&sb, pool, true)
			sb.WriteString("\n")
		}
	}

	return sb.String(), hm.String(), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDATOR IMPLEMENTATION
// ─────────────────────────────────────────────────────────────────────────────

// validator implements Validator
type validator struct {
	sshClient ssh.Client
}

// NewValidator membuat instance Validator baru
func NewValidator() Validator {
	return &validator{sshClient: nil}
}

// NewValidatorWithSSH membuat instance Validator dengan SSH client
func NewValidatorWithSSH(sshClient ssh.Client) Validator {
	return &validator{sshClient: sshClient}
}

// Validate memvalidasi konfigurasi HAProxy dengan mengupload ke node dan menjalankan `haproxy -c`.
func (v *validator) Validate(ctx context.Context, conn *ssh.Connection, configContent string) (bool, string, error) {
	if v.sshClient == nil {
		return validateSyntax(configContent)
	}

	tmpPath := "/tmp/hapm_validate.cfg"
	if err := v.sshClient.UploadFile(ctx, conn, []byte(configContent), tmpPath); err != nil {
		return false, "", fmt.Errorf("validator: upload config: %w", err)
	}

	output, err := v.sshClient.RunCommand(ctx, conn, fmt.Sprintf("sudo haproxy -c -f %s 2>&1", tmpPath))
	if err != nil {
		return false, output, nil
	}

	_, _ = v.sshClient.RunCommand(ctx, conn, fmt.Sprintf("rm -f %s", tmpPath))
	return true, "", nil
}

// validateSyntax melakukan validasi sintaks dasar tanpa SSH
func validateSyntax(content string) (bool, string, error) {
	if strings.TrimSpace(content) == "" {
		return false, "configuration is empty", nil
	}
	if !strings.Contains(content, "frontend") && !strings.Contains(content, "backend") {
		return false, "configuration must contain at least one frontend or backend", nil
	}
	return true, "", nil
}

// ─────────────────────────────────────────────────────────────────────────────
// STATS COLLECTOR IMPLEMENTATION
// ─────────────────────────────────────────────────────────────────────────────

// statsCollector implements StatsCollector
type statsCollector struct {
	sshClient ssh.Client
}

// NewStatsCollector membuat instance StatsCollector baru
func NewStatsCollector() StatsCollector {
	return &statsCollector{}
}

// NewStatsCollectorWithSSH membuat instance StatsCollector dengan SSH client
func NewStatsCollectorWithSSH(sshClient ssh.Client) StatsCollector {
	return &statsCollector{sshClient: sshClient}
}

// GetStats mengambil statistik lengkap HAProxy dari node
func (s *statsCollector) GetStats(ctx context.Context, conn *ssh.Connection) (*domain.NodeStats, error) {
	frontends, err := s.GetFrontendStats(ctx, conn)
	if err != nil {
		return nil, err
	}
	backends, err := s.GetBackendStats(ctx, conn)
	if err != nil {
		return nil, err
	}
	return &domain.NodeStats{
		NodeID:    0,
		NodeName:  conn.Host,
		Frontends: frontends,
		Backends:  backends,
	}, nil
}

// GetFrontendStats mengambil statistik frontend dari HAProxy stats socket
func (s *statsCollector) GetFrontendStats(ctx context.Context, conn *ssh.Connection) ([]*domain.FrontendStats, error) {
	if s.sshClient == nil {
		return []*domain.FrontendStats{}, nil
	}
	output, err := s.sshClient.RunCommand(ctx, conn,
		`echo "show stat" | socat - /run/haproxy/admin.sock 2>/dev/null || echo ""`)
	if err != nil {
		return nil, fmt.Errorf("stats: get frontend stats: %w", err)
	}
	return parseStatsCSV(output, "FRONTEND"), nil
}

// GetBackendStats mengambil statistik backend dari HAProxy stats socket
func (s *statsCollector) GetBackendStats(ctx context.Context, conn *ssh.Connection) ([]*domain.BackendStats, error) {
	if s.sshClient == nil {
		return []*domain.BackendStats{}, nil
	}
	output, err := s.sshClient.RunCommand(ctx, conn,
		`echo "show stat" | socat - /run/haproxy/admin.sock 2>/dev/null || echo ""`)
	if err != nil {
		return nil, fmt.Errorf("stats: get backend stats: %w", err)
	}
	return parseBackendStatsCSV(output), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// PROVISIONER IMPLEMENTATION
// ─────────────────────────────────────────────────────────────────────────────

// hapLTSVersion adalah versi HAProxy LTS yang diinstall via provisioner.
// Ganti nilai ini untuk upgrade ke LTS berikutnya.
const hapLTSVersion = "3.0"

// provisioner implements Provisioner
type provisioner struct {
	sshClient ssh.Client
}

// NewProvisioner membuat instance Provisioner baru
func NewProvisioner(sshClient ssh.Client) Provisioner {
	return &provisioner{sshClient: sshClient}
}

// Install menginstall HAProxy 3.x (latest stable) pada node melalui SSH.
// Mendukung Debian/Ubuntu (via official PPA) dan RHEL/CentOS/AlmaLinux/Rocky.
func (p *provisioner) Install(ctx context.Context, conn *ssh.Connection) error {
	// Deteksi OS
	osID, err := p.sshClient.RunCommand(ctx, conn,
		`grep -i '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]'`)
	if err != nil {
		return fmt.Errorf("provisioner: detect OS: %w", err)
	}
	osID = strings.TrimSpace(osID)

	switch {
	case osID == "ubuntu" || osID == "debian":
		if err := p.installDebian(ctx, conn); err != nil {
			return err
		}
	case osID == "centos" || osID == "rhel" || osID == "almalinux" || osID == "rocky" || osID == "fedora":
		if err := p.installRHEL(ctx, conn); err != nil {
			return err
		}
	default:
		return fmt.Errorf("provisioner: OS tidak didukung: %s (gunakan Debian/Ubuntu atau RHEL/AlmaLinux/Rocky)", osID)
	}

	// Setup direktori — semua butuh sudo karena menulis ke /etc dan mengelola systemd
	setupCmds := []string{
		"sudo mkdir -p /etc/haproxy/certs && sudo chmod 700 /etc/haproxy/certs",
		"sudo mkdir -p /etc/haproxy/maps",
		"sudo mkdir -p /etc/haproxy/errors",
		"sudo mkdir -p /run/haproxy",
		"sudo systemctl enable haproxy",
		"sudo systemctl start haproxy || true",
	}
	for _, cmd := range setupCmds {
		if out, err := p.sshClient.RunCommand(ctx, conn, cmd); err != nil {
			return fmt.Errorf("provisioner: setup direktori gagal [%s]: %v — output: %s", cmd, err, strings.TrimSpace(out))
		}
	}

	// Install acme.sh untuk Let's Encrypt
	if err := p.installAcmeSh(ctx, conn); err != nil {
		// Non-fatal — bisa diinstall manual
		fmt.Printf("[WARN] provisioner: install acme.sh gagal: %v\n", err)
	}

	return nil
}

// installDebian menginstall HAProxy LTS pada Debian atau Ubuntu via SSH.
//
//   - Ubuntu  → Launchpad PPA (ppa:vbernat/haproxy-X.Y)
//   - Debian  → haproxy.debian.net (hanya menyediakan distro Debian)
//
// Semua command sistem dijalankan dengan sudo — user SSH harus memiliki sudo NOPASSWD.
// Menghapus semua sisa konfigurasi repo HAProxy lama sebelum install ulang.
func (p *provisioner) installDebian(ctx context.Context, conn *ssh.Connection) error {
	// Deteksi OS ID untuk membedakan Ubuntu vs Debian
	osIDRaw, _ := p.sshClient.RunCommand(ctx, conn,
		`grep -i '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]'`)
	osID := strings.TrimSpace(osIDRaw)

	// Deteksi codename (jammy, bookworm, dll.) — tidak butuh sudo
	codename, err := p.sshClient.RunCommand(ctx, conn,
		`lsb_release -sc 2>/dev/null || grep -i '^VERSION_CODENAME=' /etc/os-release | cut -d= -f2 | tr -d '"'`)
	if err != nil || strings.TrimSpace(codename) == "" {
		return fmt.Errorf("provisioner: tidak bisa deteksi codename Debian/Ubuntu")
	}
	codename = strings.TrimSpace(codename)

	// ── Tahap 1: bersihkan semua sisa konfigurasi HAProxy lama ──────────────────
	// Gunakan wildcard agar semua varian nama file tertangkap (haproxy.list,
	// vbernat-ubuntu-haproxy-*.list, dll.). Selalu sukses (|| true).
	cleanupCmd := strings.Join([]string{
		`sudo find /etc/apt/sources.list.d/ -name '*haproxy*' -delete 2>/dev/null`,
		`sudo find /usr/share/keyrings/ -name '*haproxy*' -delete 2>/dev/null`,
		`sudo find /etc/apt/keyrings/ -name '*haproxy*' -delete 2>/dev/null`,
		`sudo rm -f /var/lib/apt/lists/*haproxy* 2>/dev/null`,
		`true`,
	}, " ; ")
	if _, err := p.sshClient.RunCommand(ctx, conn, cleanupCmd); err != nil {
		return fmt.Errorf("provisioner: cleanup repo lama gagal: %v", err)
	}

	// ── Tahap 2: install dependency ──────────────────────────────────────────────
	depCmds := []string{
		"sudo apt-get update -qq",
		"sudo apt-get install -y --no-install-recommends curl socat",
	}
	for _, cmd := range depCmds {
		if out, err := p.sshClient.RunCommand(ctx, conn, cmd); err != nil {
			return fmt.Errorf("provisioner: install dependency gagal [%s]: %v — output: %s", cmd, err, strings.TrimSpace(out))
		}
	}

	// ── Tahap 3: daftarkan repo HAProxy LTS ──────────────────────────────────────
	var repoCmds []string
	if osID == "ubuntu" {
		// Ubuntu: gunakan Launchpad PPA (haproxy.debian.net TIDAK menyediakan Ubuntu)
		repoCmds = []string{
			"sudo apt-get install -y --no-install-recommends software-properties-common",
			fmt.Sprintf("sudo add-apt-repository -y ppa:vbernat/haproxy-%s", hapLTSVersion),
		}
	} else {
		// Debian (bookworm, bullseye, dll.): gunakan haproxy.debian.net
		repoCmds = []string{
			"sudo mkdir -p /etc/apt/keyrings",
			"sudo curl -fsSL https://haproxy.debian.net/haproxy-archive-keyring.gpg -o /etc/apt/keyrings/haproxy-archive-keyring.gpg",
			fmt.Sprintf(
				`echo "deb [signed-by=/etc/apt/keyrings/haproxy-archive-keyring.gpg] https://haproxy.debian.net %s-backports-%s main" | sudo tee /etc/apt/sources.list.d/haproxy.list > /dev/null`,
				codename, hapLTSVersion,
			),
		}
	}
	for _, cmd := range repoCmds {
		if out, err := p.sshClient.RunCommand(ctx, conn, cmd); err != nil {
			return fmt.Errorf("provisioner: setup repo HAProxy gagal [%s]: %v — output: %s", cmd, err, strings.TrimSpace(out))
		}
	}

	// ── Tahap 4: update apt dan install HAProxy LTS ───────────────────────────────
	installCmds := []string{
		"sudo apt-get update -qq",
		fmt.Sprintf("sudo apt-get install -y --no-install-recommends haproxy=%s.*", hapLTSVersion),
		"haproxy -v",
	}
	for _, cmd := range installCmds {
		if out, err := p.sshClient.RunCommand(ctx, conn, cmd); err != nil {
			return fmt.Errorf("provisioner: install HAProxy gagal [%s]: %v — output: %s", cmd, err, strings.TrimSpace(out))
		}
	}

	return nil
}

// installRHEL menginstall HAProxy dari EPEL pada sistem berbasis RHEL.
// Semua command sistem dijalankan dengan sudo — user SSH harus memiliki sudo NOPASSWD.
func (p *provisioner) installRHEL(ctx context.Context, conn *ssh.Connection) error {
	cmds := []string{
		"sudo yum install -y epel-release || sudo dnf install -y epel-release || true",
		"sudo yum install -y haproxy socat curl || sudo dnf install -y haproxy socat curl",
		"haproxy -v",
	}
	for _, cmd := range cmds {
		if out, err := p.sshClient.RunCommand(ctx, conn, cmd); err != nil {
			return fmt.Errorf("provisioner: rhel install gagal saat menjalankan [%s]: %v — output: %s", cmd, err, strings.TrimSpace(out))
		}
	}
	return nil
}

// installAcmeSh menginstall acme.sh untuk manajemen Let's Encrypt certificate
func (p *provisioner) installAcmeSh(ctx context.Context, conn *ssh.Connection) error {
	// Cek apakah sudah terinstall
	if out, _ := p.sshClient.RunCommand(ctx, conn, "~/.acme.sh/acme.sh --version 2>/dev/null"); strings.Contains(out, "v") {
		return nil // sudah terinstall
	}

	cmds := []string{
		"curl -fsSL https://get.acme.sh | sh -s email=admin@localhost",
		"~/.acme.sh/acme.sh --set-default-ca --server letsencrypt",
	}
	for _, cmd := range cmds {
		if out, err := p.sshClient.RunCommand(ctx, conn, cmd); err != nil {
			return fmt.Errorf("acme.sh install (%s): %w\noutput: %s", cmd, err, out)
		}
	}
	return nil
}

// GetVersion mengambil versi HAProxy yang terinstall pada node
func (p *provisioner) GetVersion(ctx context.Context, conn *ssh.Connection) (string, error) {
	output, err := p.sshClient.RunCommand(ctx, conn, "haproxy -v 2>&1 | head -1")
	if err != nil {
		return "", fmt.Errorf("provisioner: get version: %w", err)
	}

	// Output: "HAProxy version 3.0.x-xxx 2024/xx/xx"
	parts := strings.Fields(output)
	for i, part := range parts {
		if strings.ToLower(part) == "version" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return strings.TrimSpace(output), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

// writeHealthCheckOptions menulis baris option health check ke string builder.
// Dipanggil sekali per backend/listen block, sebelum daftar server.
func writeHealthCheckOptions(sb *strings.Builder, cfg domain.HealthCheckConfig) {
	switch cfg.Type {
	case domain.HealthCheckHTTP, domain.HealthCheckHTTPS:
		path := cfg.Path
		if path == "" {
			path = "/"
		}
		expect := cfg.Expect
		if expect == "" {
			expect = "200-399"
		}
		// Gunakan HTTP/1.1 agar backend tidak menolak karena missing Host header.
		// option httpchk tanpa arg mengaktifkan new-style check (HAProxy 2.2+),
		// http-check send meth/uri/hdr menggantikan lama option httpchk GET <path>.
		sb.WriteString("    option httpchk\n")
		sb.WriteString(fmt.Sprintf("    http-check send meth GET uri %s ver HTTP/1.1 hdr Host localhost\n", path))
		sb.WriteString(fmt.Sprintf("    http-check expect status %s\n", expect))
	case domain.HealthCheckSSH:
		sb.WriteString("    option tcp-check\n")
		sb.WriteString("    tcp-check expect rstring SSH-2.0-OpenSSH.*\n")
	case domain.HealthCheckMySQL:
		user := cfg.User
		if user == "" {
			user = "haproxy"
		}
		sb.WriteString(fmt.Sprintf("    option mysql-check user %s\n", user))
	case domain.HealthCheckPostgreSQL:
		user := cfg.User
		if user == "" {
			user = "haproxy"
		}
		sb.WriteString(fmt.Sprintf("    option pgsql-check user %s\n", user))
	case domain.HealthCheckRedis:
		sb.WriteString("    option tcp-check\n")
		sb.WriteString("    tcp-check send PING\\r\\n\n")
		sb.WriteString("    tcp-check expect string +PONG\n")
	case domain.HealthCheckCustom:
		for _, line := range strings.Split(cfg.Custom, "\n") {
			if t := strings.TrimSpace(line); t != "" {
				sb.WriteString("    " + t + "\n")
			}
		}
	// TCP, none, "": tidak ada option lines
	}
}

// serverSSLFlag mengembalikan suffix ssl verify berdasarkan protocol + ssl_mode pool.
// Diprioritaskan dari BackendProtocol; fallback ke HealthCheckHTTPS untuk backward compat.
func serverSSLFlag(pool *domain.BackendPool) string {
	if pool.Protocol == domain.BackendProtocolHTTPS {
		switch pool.SSLMode {
		case domain.BackendSSLModeTrusted:
			return " ssl verify required"
		case domain.BackendSSLModeSelfSigned:
			return " ssl verify none"
		}
	}
	// Backward compat: health check HTTPS tanpa protocol=https tetap butuh ssl
	if pool.HealthCheckConf.Type == domain.HealthCheckHTTPS {
		return " ssl verify none"
	}
	return ""
}

// writeForwardHeaders menulis http-request set-header X-Forwarded-* ke backend block.
// Tidak ditulis untuk protocol tcp (mode tcp tidak mendukung http-request directives).
func writeForwardHeaders(sb *strings.Builder, pool *domain.BackendPool) {
	if !pool.ForwardHeaders || pool.Protocol == domain.BackendProtocolTCP {
		return
	}
	sb.WriteString("    option forwardfor\n")
	sb.WriteString("    http-request set-header X-Forwarded-Proto https\n")
	sb.WriteString("    http-request set-header X-Forwarded-Ssl on\n")
	sb.WriteString("    http-request set-header X-Forwarded-Port 443\n")
	sb.WriteString("    http-request set-header X-Forwarded-Proto https if { hdr(CF-Visitor) -m sub https }\n")
	sb.WriteString("    http-request set-header X-Forwarded-Ssl on if { hdr(CF-Visitor) -m sub https }\n")
}

// writeServerList menulis daftar server dengan ssl + health check flag yang sesuai.
func writeServerList(sb *strings.Builder, pool *domain.BackendPool, withWeight bool) {
	sslFlag := serverSSLFlag(pool)
	checkEnabled := pool.HealthCheckConf.IsEnabled()
	for _, srv := range pool.Servers {
		if !srv.Enabled {
			continue
		}
		var line string
		if withWeight {
			line = fmt.Sprintf("    server %s %s:%d weight %d",
				sanitizeName(srv.Name), srv.IPAddress, srv.Port, srv.Weight)
		} else {
			line = fmt.Sprintf("    server %s %s:%d",
				sanitizeName(srv.Name), srv.IPAddress, srv.Port)
		}
		if sslFlag != "" {
			line += sslFlag
		}
		if checkEnabled {
			line += " inter 10s check"
		}
		if srv.Backup {
			line += " backup"
		}
		sb.WriteString(line + "\n")
	}
}

// isTCPHealthCheck melaporkan apakah health check type memerlukan mode tcp
func isTCPHealthCheck(t domain.HealthCheckType) bool {
	switch t {
	case domain.HealthCheckTCP, domain.HealthCheckSSH,
		domain.HealthCheckMySQL, domain.HealthCheckPostgreSQL,
		domain.HealthCheckRedis, domain.HealthCheckCustom:
		return true
	}
	return false
}

// sanitizeName mengonversi string menjadi nama yang valid untuk HAProxy config
func sanitizeName(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			sb.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			sb.WriteRune(r)
		case r >= '0' && r <= '9':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

// hashConfig menghitung SHA256 hash dari config content
func hashConfig(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// HashConfig adalah exported wrapper untuk hashConfig
func HashConfig(content string) string {
	return hashConfig(content)
}

// parseStatsCSV mem-parse output CSV dari HAProxy stats socket untuk frontend entries
func parseStatsCSV(csv, svType string) []*domain.FrontendStats {
	var result []*domain.FrontendStats
	for _, line := range strings.Split(csv, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 80 {
			continue
		}
		if fields[1] != svType {
			continue
		}
		result = append(result, &domain.FrontendStats{
			Name:   fields[0],
			Status: safeField(fields, 17),
		})
	}
	return result
}

// parseBackendStatsCSV mem-parse output CSV untuk backend entries
func parseBackendStatsCSV(csv string) []*domain.BackendStats {
	var result []*domain.BackendStats
	var currentBackend *domain.BackendStats

	for _, line := range strings.Split(csv, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 80 {
			continue
		}

		svname := fields[1]
		pxname := fields[0]

		if svname == "BACKEND" {
			if currentBackend != nil {
				result = append(result, currentBackend)
			}
			currentBackend = &domain.BackendStats{
				Name:   pxname,
				Status: safeField(fields, 17),
			}
		} else if svname != "FRONTEND" && currentBackend != nil {
			currentBackend.Servers = append(currentBackend.Servers, &domain.ServerStat{
				Name:   svname,
				Status: safeField(fields, 17),
			})
		}
	}

	if currentBackend != nil {
		result = append(result, currentBackend)
	}
	return result
}

// safeField mengambil field dari slice dengan bounds checking
func safeField(fields []string, idx int) string {
	if idx < len(fields) {
		return fields[idx]
	}
	return ""
}

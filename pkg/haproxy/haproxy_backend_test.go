package haproxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aefw/hapm/internal/domain"
)

// makePool adalah helper untuk membuat BackendPool minimal untuk test.
func makePool(id int, name string, protocol domain.BackendProtocol, sslMode domain.BackendSSLMode, fwdHeaders bool, servers ...domain.BackendServer) *domain.BackendPool {
	return &domain.BackendPool{
		ID:             id,
		Name:           name,
		Algorithm:      domain.AlgorithmRoundRobin,
		TimeoutConnect: 5000,
		TimeoutServer:  30000,
		Protocol:       protocol,
		SSLMode:        sslMode,
		ForwardHeaders: fwdHeaders,
		HealthCheckConf: domain.HealthCheckConfig{
			Type: domain.HealthCheckHTTP,
			Path: "/",
		},
		Servers: servers,
	}
}

func srv(name, ip string, port int) domain.BackendServer {
	return domain.BackendServer{
		Name: name, IPAddress: ip, Port: port,
		Weight: 1, Enabled: true,
		Created: time.Now(), Timestamp: time.Now(),
	}
}

func makeNode(behindCF bool) *domain.Node {
	return &domain.Node{BehindCloudflare: behindCF}
}

// generateConfig menjalankan generator dan mengembalikan config string.
func generateConfig(t *testing.T, pools []*domain.BackendPool, domains []*domain.DomainEntry) string {
	t.Helper()
	g := NewGenerator()
	cfg, _, err := g.Generate(context.Background(), makeNode(false), domains, pools, nil, nil, nil)
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}
	return cfg
}

// ─── serverSSLFlag ────────────────────────────────────────────────────────────

func TestServerSSLFlag_HTTP(t *testing.T) {
	pool := makePool(1, "test", domain.BackendProtocolHTTP, domain.BackendSSLModeNone, false)
	if got := serverSSLFlag(pool); got != "" {
		t.Errorf("http pool: want empty ssl flag, got %q", got)
	}
}

func TestServerSSLFlag_HTTPSSelfsigned(t *testing.T) {
	pool := makePool(1, "test", domain.BackendProtocolHTTPS, domain.BackendSSLModeSelfSigned, false)
	want := " ssl verify none"
	if got := serverSSLFlag(pool); got != want {
		t.Errorf("https self_signed: want %q, got %q", want, got)
	}
}

func TestServerSSLFlag_HTTPSTrusted(t *testing.T) {
	pool := makePool(1, "test", domain.BackendProtocolHTTPS, domain.BackendSSLModeTrusted, false)
	want := " ssl verify required"
	if got := serverSSLFlag(pool); got != want {
		t.Errorf("https trusted: want %q, got %q", want, got)
	}
}

func TestServerSSLFlag_TCPNoSSL(t *testing.T) {
	pool := makePool(1, "test", domain.BackendProtocolTCP, domain.BackendSSLModeNone, false)
	if got := serverSSLFlag(pool); got != "" {
		t.Errorf("tcp pool: want empty ssl flag, got %q", got)
	}
}

func TestServerSSLFlag_BackwardCompatHealthCheckHTTPS(t *testing.T) {
	// Pool lama: protocol=http (default), tapi health check HTTPS → tetap ssl verify none
	pool := &domain.BackendPool{
		Protocol: domain.BackendProtocolHTTP,
		SSLMode:  domain.BackendSSLModeNone,
		HealthCheckConf: domain.HealthCheckConfig{
			Type: domain.HealthCheckHTTPS,
		},
	}
	want := " ssl verify none"
	if got := serverSSLFlag(pool); got != want {
		t.Errorf("backward compat HTTPS health check: want %q, got %q", want, got)
	}
}

// ─── writeForwardHeaders ──────────────────────────────────────────────────────

func TestWriteForwardHeaders_EnabledHTTP(t *testing.T) {
	pool := makePool(1, "test", domain.BackendProtocolHTTP, domain.BackendSSLModeNone, true)
	var sb strings.Builder
	writeForwardHeaders(&sb, pool)
	out := sb.String()
	for _, want := range []string{
		"option forwardfor",
		"X-Forwarded-Proto https",
		"X-Forwarded-Ssl on",
		"X-Forwarded-Port 443",
		"CF-Visitor",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("forward_headers=true: output harus mengandung %q\ngot:\n%s", want, out)
		}
	}
}

func TestWriteForwardHeaders_DisabledSkipped(t *testing.T) {
	pool := makePool(1, "test", domain.BackendProtocolHTTP, domain.BackendSSLModeNone, false)
	var sb strings.Builder
	writeForwardHeaders(&sb, pool)
	if sb.String() != "" {
		t.Errorf("forward_headers=false: expect empty output, got %q", sb.String())
	}
}

func TestWriteForwardHeaders_TCPSkipped(t *testing.T) {
	pool := makePool(1, "test", domain.BackendProtocolTCP, domain.BackendSSLModeNone, true)
	var sb strings.Builder
	writeForwardHeaders(&sb, pool)
	if sb.String() != "" {
		t.Errorf("protocol=tcp + forward_headers=true: expect empty (tcp mode has no http-request), got %q", sb.String())
	}
}

// ─── Generator end-to-end per protokol ───────────────────────────────────────

func domainEntry(domainName string, poolID int) *domain.DomainEntry {
	return &domain.DomainEntry{
		DomainName:    domainName,
		BackendPoolID: poolID,
		SSLMode:       domain.SSLModeNone,
		HTTPRedirect:  false,
		Enabled:       true,
	}
}

func TestGenerator_BackendHTTP(t *testing.T) {
	pool := makePool(1, "web", domain.BackendProtocolHTTP, domain.BackendSSLModeNone, false,
		srv("srv1", "10.0.0.1", 80))
	cfg := generateConfig(t, []*domain.BackendPool{pool}, []*domain.DomainEntry{domainEntry("example.com", 1)})

	if strings.Contains(cfg, "ssl verify") {
		t.Errorf("http backend: tidak boleh ada 'ssl verify'\n%s", cfg)
	}
	if !strings.Contains(cfg, "server srv1 10.0.0.1:80") {
		t.Errorf("http backend: server line tidak ditemukan\n%s", cfg)
	}
}

func TestGenerator_BackendHTTPSSelfSigned(t *testing.T) {
	pool := makePool(1, "api", domain.BackendProtocolHTTPS, domain.BackendSSLModeSelfSigned, false,
		srv("srv1", "10.0.0.1", 443))
	cfg := generateConfig(t, []*domain.BackendPool{pool}, []*domain.DomainEntry{domainEntry("api.example.com", 1)})

	if !strings.Contains(cfg, "ssl verify none") {
		t.Errorf("https self_signed: harus ada 'ssl verify none'\n%s", cfg)
	}
	if strings.Contains(cfg, "ssl verify required") {
		t.Errorf("https self_signed: tidak boleh ada 'ssl verify required'\n%s", cfg)
	}
}

func TestGenerator_BackendHTTPSTrusted(t *testing.T) {
	pool := makePool(1, "secure", domain.BackendProtocolHTTPS, domain.BackendSSLModeTrusted, false,
		srv("srv1", "10.0.0.1", 443))
	cfg := generateConfig(t, []*domain.BackendPool{pool}, []*domain.DomainEntry{domainEntry("secure.example.com", 1)})

	if !strings.Contains(cfg, "ssl verify required") {
		t.Errorf("https trusted: harus ada 'ssl verify required'\n%s", cfg)
	}
}

func TestGenerator_BackendTCP_ModeTCP(t *testing.T) {
	pool := &domain.BackendPool{
		ID:             1,
		Name:           "rawstream",
		Algorithm:      domain.AlgorithmRoundRobin,
		TimeoutConnect: 5000,
		TimeoutServer:  30000,
		Protocol:       domain.BackendProtocolTCP,
		SSLMode:        domain.BackendSSLModeNone,
		ForwardHeaders: false,
		HealthCheckConf: domain.HealthCheckConfig{Type: domain.HealthCheckNone},
		Servers:        []domain.BackendServer{srv("srv1", "10.0.0.1", 443)},
	}
	cfg := generateConfig(t, []*domain.BackendPool{pool}, []*domain.DomainEntry{domainEntry("stream.example.com", 1)})

	// backend block harus ada mode tcp
	backendSection := extractBackendSection(cfg, "backend_stream_example_com")
	if !strings.Contains(backendSection, "mode tcp") {
		t.Errorf("tcp protocol: backend harus mode tcp\n%s", backendSection)
	}
	if strings.Contains(backendSection, "ssl verify") {
		t.Errorf("tcp protocol: tidak boleh ada ssl verify\n%s", backendSection)
	}
}

func TestGenerator_ForwardHeaders_InBackend(t *testing.T) {
	pool := makePool(1, "cms", domain.BackendProtocolHTTP, domain.BackendSSLModeNone, true,
		srv("srv1", "10.0.0.1", 80))
	cfg := generateConfig(t, []*domain.BackendPool{pool}, []*domain.DomainEntry{domainEntry("cms.example.com", 1)})

	backendSection := extractBackendSection(cfg, "backend_cms_example_com")
	for _, want := range []string{"option forwardfor", "X-Forwarded-Proto https", "X-Forwarded-Ssl on", "X-Forwarded-Port 443"} {
		if !strings.Contains(backendSection, want) {
			t.Errorf("forward_headers=true: backend harus mengandung %q\n%s", want, backendSection)
		}
	}
}

func TestGenerator_ForwardHeaders_Disabled(t *testing.T) {
	pool := makePool(1, "app", domain.BackendProtocolHTTP, domain.BackendSSLModeNone, false,
		srv("srv1", "10.0.0.1", 80))
	cfg := generateConfig(t, []*domain.BackendPool{pool}, []*domain.DomainEntry{domainEntry("app.example.com", 1)})

	backendSection := extractBackendSection(cfg, "backend_app_example_com")
	// X-Forwarded-Port tidak boleh ada di backend block ketika forward_headers=false
	if strings.Contains(backendSection, "X-Forwarded-Port") {
		t.Errorf("forward_headers=false: backend tidak boleh mengandung X-Forwarded-Port\n%s", backendSection)
	}
}

// extractBackendSection mengambil satu backend block dari config string
func extractBackendSection(cfg, backendName string) string {
	lines := strings.Split(cfg, "\n")
	var result []string
	inBlock := false
	for _, line := range lines {
		if strings.HasPrefix(line, "backend "+backendName) {
			inBlock = true
		} else if inBlock && line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}
		if inBlock {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

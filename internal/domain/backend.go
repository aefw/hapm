package domain

import "time"

// Algorithm adalah algoritma load balancing HAProxy
type Algorithm string

const (
	AlgorithmRoundRobin Algorithm = "roundrobin"
	AlgorithmLeastConn  Algorithm = "leastconn"
	AlgorithmSource     Algorithm = "source"
)

// HealthCheckType adalah jenis health check yang didukung HAProxy
type HealthCheckType string

const (
	HealthCheckNone       HealthCheckType = "none"
	HealthCheckTCP        HealthCheckType = "TCP"
	HealthCheckHTTP       HealthCheckType = "HTTP"
	HealthCheckHTTPS      HealthCheckType = "HTTPS"
	HealthCheckSSH        HealthCheckType = "SSH"
	HealthCheckMySQL      HealthCheckType = "MYSQL"
	HealthCheckPostgreSQL HealthCheckType = "POSTGRESQL"
	HealthCheckRedis      HealthCheckType = "REDIS"
	HealthCheckCustom     HealthCheckType = "CUSTOM"
)

// HealthCheckConfig menyimpan konfigurasi health check untuk backend pool.
// Field yang digunakan bergantung pada Type.
type HealthCheckConfig struct {
	Type   HealthCheckType `json:"type"`
	Path   string          `json:"path,omitempty"`   // HTTP, HTTPS: path endpoint, default "/"
	Expect string          `json:"expect,omitempty"` // HTTP/HTTPS: status code, default "200-399"
	User   string          `json:"user,omitempty"`   // MYSQL, POSTGRESQL: monitoring username
	Custom string          `json:"custom,omitempty"` // CUSTOM: raw HAProxy check directives
}

// IsEnabled melaporkan apakah health check aktif (bukan none/kosong)
func (h HealthCheckConfig) IsEnabled() bool {
	return h.Type != HealthCheckNone && h.Type != ""
}

// BackendProtocol adalah protokol komunikasi ke backend server
type BackendProtocol string

const (
	BackendProtocolHTTP  BackendProtocol = "http"
	BackendProtocolHTTPS BackendProtocol = "https"
	BackendProtocolTCP   BackendProtocol = "tcp"
)

// BackendSSLMode adalah mode verifikasi SSL untuk backend HTTPS
type BackendSSLMode string

const (
	BackendSSLModeNone       BackendSSLMode = "none"
	BackendSSLModeTrusted    BackendSSLMode = "trusted"
	BackendSSLModeSelfSigned BackendSSLMode = "self_signed"
)

// BackendPool adalah entity pool backend HAProxy
type BackendPool struct {
	ID              int               `json:"id_backend_pools"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Algorithm       Algorithm         `json:"algorithm"`
	TimeoutConnect  int               `json:"timeout_connect"` // ms
	TimeoutServer   int               `json:"timeout_server"`  // ms
	Protocol        BackendProtocol   `json:"protocol"`
	SSLMode         BackendSSLMode    `json:"ssl_mode"`
	ForwardHeaders  bool              `json:"forward_headers"`
	HealthCheck     bool              `json:"health_check"`    // derived: true ketika HealthCheckConf.IsEnabled()
	HealthCheckConf HealthCheckConfig `json:"health_check_config"`
	Servers         []BackendServer   `json:"servers,omitempty"`
	Created         time.Time         `json:"created"`
	Timestamp       time.Time         `json:"timestamp"`
}

// BackendServer adalah entity server di dalam BackendPool
type BackendServer struct {
	ID            int       `json:"id_backend_servers"`
	BackendPoolID int       `json:"id_backend_pools"`
	Name          string    `json:"name"`
	IPAddress     string    `json:"ip_address"`
	Port          int       `json:"port"`
	Weight        int       `json:"weight"`
	Backup        bool      `json:"backup"`
	Enabled       bool      `json:"enabled"`
	Created       time.Time `json:"created"`
	Timestamp     time.Time `json:"timestamp"`
}

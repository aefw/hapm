package domain

import "time"

// NodeStatus adalah status koneksi node HAProxy
type NodeStatus string

const (
	NodeStatusOnline  NodeStatus = "online"
	NodeStatusOffline NodeStatus = "offline"
	NodeStatusUnknown NodeStatus = "unknown"
)

// Node adalah entity node HAProxy yang dikelola HAPM
type Node struct {
	ID               int        `json:"id_nodes"`
	Name             string     `json:"name"`
	Hostname         string     `json:"hostname"`
	IPAddress        string     `json:"ip_address"`
	SSHPort          int        `json:"ssh_port"`
	SSHUser          string     `json:"ssh_user"`
	SSHPrivateKey    string     `json:"-"` // encrypted, tidak dikembalikan ke client
	Description      string     `json:"description"`
	Status           NodeStatus `json:"status"`
	LastChecked      *time.Time `json:"last_checked,omitempty"`
	HAProxyVersion       string     `json:"haproxy_version,omitempty"`
	BehindCloudflare     bool       `json:"behind_cloudflare"`
	HTTPSFrontendEnabled bool       `json:"https_frontend_enabled"`
	// Provision tracking — diperbarui oleh background goroutine saat provision berjalan
	ProvisionStep  int    `json:"provision_step"`            // 0=idle, 1-6=in-progress/failed, 7=done
	ProvisionError string `json:"provision_error,omitempty"` // pesan error jika gagal, kosong jika sukses
	// Statistics — konfigurasi HAProxy stats page per node
	StatsEnabled      bool   `json:"stats_enabled"`
	StatsBindAddr     string `json:"stats_bind_addr"`
	StatsPort         int    `json:"stats_port"`
	StatsURI          string `json:"stats_uri"`
	StatsRefresh      string `json:"stats_refresh"`
	StatsHideVersion  bool   `json:"stats_hide_version"`
	StatsReadOnly     bool   `json:"stats_readonly"`
	StatsAdmin        bool   `json:"stats_admin"`
	StatsAllowedGroups []int `json:"stats_allowed_groups"` // ID dari auth_groups
	Created   time.Time `json:"created"`
	Timestamp time.Time `json:"timestamp"`
}

// NodeSummary adalah versi ringkas Node untuk list response
type NodeSummary struct {
	ID               int        `json:"id_nodes"`
	Name             string     `json:"name"`
	Hostname         string     `json:"hostname"`
	IPAddress        string     `json:"ip_address"`
	SSHPort          int        `json:"ssh_port"`
	SSHUser          string     `json:"ssh_user"`
	Status               NodeStatus `json:"status"`
	HAProxyVersion       string     `json:"haproxy_version,omitempty"`
	LastChecked          *time.Time `json:"last_checked,omitempty"`
	BehindCloudflare     bool       `json:"behind_cloudflare"`
	HTTPSFrontendEnabled bool       `json:"https_frontend_enabled"`
	ProvisionStep        int        `json:"provision_step"`
	ProvisionError       string     `json:"provision_error,omitempty"`
}

// SSHKeyDecrypted adalah struct untuk membawa private key yang sudah didekripsi
// Tidak pernah disimpan ke database, hanya digunakan in-memory
type SSHKeyDecrypted struct {
	NodeID     int
	PrivateKey string
}

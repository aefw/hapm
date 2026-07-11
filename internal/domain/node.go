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
	HAProxyVersion   string     `json:"haproxy_version,omitempty"`
	BehindCloudflare     bool       `json:"behind_cloudflare"`      // true = ekstrak IP dari CF-Connecting-IP
	HTTPSFrontendEnabled bool       `json:"https_frontend_enabled"` // true = selalu generate frontend https_in
	Created              time.Time  `json:"created"`
	Timestamp            time.Time  `json:"timestamp"`
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
}

// SSHKeyDecrypted adalah struct untuk membawa private key yang sudah didekripsi
// Tidak pernah disimpan ke database, hanya digunakan in-memory
type SSHKeyDecrypted struct {
	NodeID     int
	PrivateKey string
}

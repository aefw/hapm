package domain

import "time"

// SSLMode adalah mode SSL untuk domain routing
type SSLMode string

const (
	SSLModeNone        SSLMode = "none"
	SSLModeTerminate   SSLMode = "terminate"
	SSLModePassthrough SSLMode = "passthrough"
)

// DomainEntry adalah entity domain routing HAPM.
// Nama "DomainEntry" untuk menghindari collision dengan package "domain".
type DomainEntry struct {
	ID            int          `json:"id_domains"`
	DomainName    string       `json:"domain_name"`
	BackendPoolID int          `json:"id_backend_pools"`
	BackendPool   *BackendPool `json:"backend_pool,omitempty"`
	SSLMode       SSLMode      `json:"ssl_mode"`
	CertUUID      *string      `json:"cert_uuid,omitempty"`
	Cert          *Certificate `json:"certificate,omitempty"`
	AuthGroupID   *int         `json:"id_auth_groups,omitempty"`
	AuthGroup     *AuthGroup   `json:"auth_group,omitempty"`
	HTTPRedirect  bool         `json:"http_redirect"`
	Enabled       bool         `json:"enabled"`
	Description   string       `json:"description"`
	Created       time.Time    `json:"created"`
	Timestamp     time.Time    `json:"timestamp"`
}

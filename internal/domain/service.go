package domain

import "time"

// ServiceType adalah tipe service HAProxy
type ServiceType string

const (
	ServiceTypeHTTP  ServiceType = "HTTP"
	ServiceTypeHTTPS ServiceType = "HTTPS"
	ServiceTypeTCP   ServiceType = "TCP"
)

// Service adalah entity service HAProxy untuk port-based load balancing.
// Berbeda dengan DomainEntry yang routing berdasarkan nama domain,
// Service routing berdasarkan port menggunakan HAProxy listen block.
type Service struct {
	ID            int          `json:"id_services"`
	Name          string       `json:"name"`
	ServiceType   ServiceType  `json:"service_type"`
	ListenPort    int          `json:"listen_port"`
	BackendPoolID int          `json:"id_backend_pools"`
	BackendPool   *BackendPool `json:"backend_pool,omitempty"`
	Description   string       `json:"description"`
	Enabled       bool         `json:"enabled"`
	Created       time.Time    `json:"created"`
	Timestamp     time.Time    `json:"timestamp"`
}

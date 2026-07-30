package domain

import (
	"context"
	"time"
)

// WAFCORSRule adalah aturan CORS untuk path tertentu
type WAFCORSRule struct {
	ID               int       `json:"id"`
	Name             string    `json:"name"`
	PathPattern      string    `json:"path_pattern"`
	AllowedOrigins   string    `json:"allowed_origins"` // JSON array string
	AllowedMethods   string    `json:"allowed_methods"`
	AllowedHeaders   string    `json:"allowed_headers"`
	ExposeHeaders    string    `json:"expose_headers"`
	AllowCredentials bool      `json:"allow_credentials"`
	MaxAgeSeconds    int       `json:"max_age_seconds"`
	Enabled          bool      `json:"enabled"`
	Priority         int       `json:"priority"`
	DomainIDs        []int     `json:"domain_ids"` // kosong = berlaku global semua domain
	Created          time.Time `json:"created"`
	Timestamp        time.Time `json:"timestamp"`
}

// WAFCORSRepository mendefinisikan kontrak akses data WAFCORSRule
type WAFCORSRepository interface {
	List(ctx context.Context) ([]*WAFCORSRule, error)
	FindByID(ctx context.Context, id int) (*WAFCORSRule, error)
	ListEnabled(ctx context.Context) ([]*WAFCORSRule, error)
	Create(ctx context.Context, rule *WAFCORSRule) error
	Update(ctx context.Context, rule *WAFCORSRule) error
	Delete(ctx context.Context, id int) error
}

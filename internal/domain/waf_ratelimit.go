package domain

import (
	"context"
	"time"
)

// WAFRateLimit adalah profil pembatasan request per IP
type WAFRateLimit struct {
	ID                     int       `json:"id"`
	Name                   string    `json:"name"`
	PathPattern            string    `json:"path_pattern"`
	MaxRequests            int       `json:"max_requests"`
	WindowSeconds          int       `json:"window_seconds"`
	BlockDurationSeconds   int       `json:"block_duration_seconds"`
	AutoBlacklistThreshold *int      `json:"auto_blacklist_threshold"`
	Enabled                bool      `json:"enabled"`
	Created                time.Time `json:"created"`
	Timestamp              time.Time `json:"timestamp"`
}

// WAFRateLimitRepository mendefinisikan kontrak akses data WAFRateLimit
type WAFRateLimitRepository interface {
	List(ctx context.Context) ([]*WAFRateLimit, error)
	FindByID(ctx context.Context, id int) (*WAFRateLimit, error)
	ListEnabled(ctx context.Context) ([]*WAFRateLimit, error)
	Create(ctx context.Context, rl *WAFRateLimit) error
	Update(ctx context.Context, rl *WAFRateLimit) error
	Delete(ctx context.Context, id int) error
}

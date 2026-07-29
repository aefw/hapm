package domain

import (
	"context"
	"time"
)

// WAFBlacklist adalah entri IP/CIDR yang diblokir secara permanen atau sementara
type WAFBlacklist struct {
	ID        int        `json:"id"`
	IPAddress string     `json:"ip_address"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
	Created   time.Time  `json:"created"`
	Timestamp time.Time  `json:"timestamp"`
}

// WAFBlacklistRepository mendefinisikan kontrak akses data WAFBlacklist
type WAFBlacklistRepository interface {
	List(ctx context.Context) ([]*WAFBlacklist, error)
	FindByID(ctx context.Context, id int) (*WAFBlacklist, error)
	IsBlacklisted(ctx context.Context, ip string) (bool, error)
	Create(ctx context.Context, bl *WAFBlacklist) error
	Delete(ctx context.Context, id int) error
	CleanExpired(ctx context.Context) error
}

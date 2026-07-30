package domain

import (
	"context"
	"time"
)

// WAFWhitelist adalah entri IP/CIDR yang diizinkan bypass semua WAF rules
type WAFWhitelist struct {
	ID          int        `json:"id"`
	IPAddress   string     `json:"ip_address"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at"`
	DomainIDs   []int      `json:"domain_ids"` // kosong = berlaku global semua domain
	Created     time.Time  `json:"created"`
	Timestamp   time.Time  `json:"timestamp"`
}

// WAFWhitelistRepository mendefinisikan kontrak akses data WAFWhitelist
type WAFWhitelistRepository interface {
	List(ctx context.Context) ([]*WAFWhitelist, error)
	FindByID(ctx context.Context, id int) (*WAFWhitelist, error)
	IsWhitelisted(ctx context.Context, ip string) (bool, error)
	Create(ctx context.Context, wl *WAFWhitelist) error
	Delete(ctx context.Context, id int) error
}

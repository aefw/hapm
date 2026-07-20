package domain

import "context"

// SNResult adalah hasil pemeriksaan dan aktivasi entitlement.
type SNResult struct {
	HasFile        bool                   `json:"has_file"`
	IsValid        bool                   `json:"is_valid"`
	IsExpired      bool                   `json:"is_expired"`
	HasModule      bool                   `json:"has_module"`
	PremiumEnabled bool                   `json:"premium_enabled"`
	Info           map[string]interface{} `json:"info,omitempty"`
}

// SNService mendefinisikan kontrak pemeriksaan entitlement.
type SNService interface {
	// Activate mengunduh license dari server menggunakan kode aktivasi,
	// lalu memverifikasi dan mengaktifkan fitur premium jika valid.
	Activate(ctx context.Context, code string) (*SNResult, error)

	// Status membaca file lokal tanpa mengunduh.
	Status(ctx context.Context) (*SNResult, error)
}

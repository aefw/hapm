package domain

// ListFilter adalah parameter pencarian dan pagination untuk semua endpoint list.
// Digunakan oleh repository, service, dan handler secara konsisten.
//
//   - Q           : keyword pencarian (case-insensitive, multi-kolom LIKE)
//   - Start       : offset halaman (0-based); 0 = halaman pertama
//   - Limit       : jumlah data per halaman; 0 = tanpa limit (digunakan oleh internal service)
//   - AuthGroupID : filter domain by id_auth_groups (nil = semua domain)
type ListFilter struct {
	Q           string
	Start       int
	Limit       int
	AuthGroupID *int // domain-specific: filter by auth group
}

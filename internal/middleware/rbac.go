package middleware

import (
	"github.com/aefw/hapm/internal/core"
	"net/http"
)

// Role constants — konsisten dengan domain/user.go
const (
	RoleSuperAdmin = "superadmin"
	RoleAdmin      = "admin"
	RoleViewer     = "viewer"
)

// roleLevel memetakan role ke level numerik untuk perbandingan hierarki.
// Semakin tinggi angka = semakin banyak akses.
var roleLevel = map[string]int{
	RoleViewer:     1,
	RoleAdmin:      2,
	RoleSuperAdmin: 3,
}

// RequireRole membungkus HandlerFunc dengan pengecekan role.
// Handler hanya dieksekusi jika user memiliki role yang diminta atau lebih tinggi.
// RequireAuth harus dipanggil sebelum RequireRole.
//
// Contoh: RequireRole(RoleAdmin, handler) → hanya admin dan superadmin
func RequireRole(minRole string, handler core.HandlerFunc) core.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params []string) {
		role := core.GetRole(r.Context())
		if role == "" {
			core.Unauthorized(w, "Autentikasi diperlukan")
			return
		}

		userLevel, ok := roleLevel[role]
		if !ok {
			core.Forbidden(w, "Role tidak dikenali")
			return
		}

		requiredLevel, ok := roleLevel[minRole]
		if !ok {
			core.InternalError(w, "Konfigurasi role tidak valid")
			return
		}

		if userLevel < requiredLevel {
			core.Forbidden(w, "Akses ditolak: role tidak mencukupi")
			return
		}

		handler(w, r, params)
	}
}

// RequireExactRole membungkus HandlerFunc yang hanya boleh diakses role tertentu.
// Berbeda dengan RequireRole yang bersifat hierarki — ini strict match.
//
// Contoh: RequireExactRole(RoleSuperAdmin, handler) → hanya superadmin saja
func RequireExactRole(exactRole string, handler core.HandlerFunc) core.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params []string) {
		role := core.GetRole(r.Context())
		if role == "" {
			core.Unauthorized(w, "Autentikasi diperlukan")
			return
		}

		if role != exactRole {
			core.Forbidden(w, "Akses ditolak: role tidak sesuai")
			return
		}

		handler(w, r, params)
	}
}

// RequireOwnerOrRole membolehkan akses jika user adalah pemilik resource (userID == ownerID)
// ATAU memiliki role minimum yang diminta.
// Berguna untuk endpoint seperti GET /users/{id} yang bisa diakses user sendiri atau admin.
func RequireOwnerOrRole(ownerID int, minRole string, handler core.HandlerFunc) core.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, params []string) {
		userID := core.GetUserID(r.Context())
		role := core.GetRole(r.Context())

		if userID == 0 || role == "" {
			core.Unauthorized(w, "Autentikasi diperlukan")
			return
		}

		// Cek apakah user adalah pemilik resource
		if userID == ownerID {
			handler(w, r, params)
			return
		}

		// Cek role hierarchy
		userLevel := roleLevel[role]
		requiredLevel := roleLevel[minRole]
		if userLevel >= requiredLevel {
			handler(w, r, params)
			return
		}

		core.Forbidden(w, "Akses ditolak")
	}
}

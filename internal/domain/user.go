package domain

import "time"

// Role constants — RBAC
const (
	RoleSuperAdmin = "superadmin"
	RoleAdmin      = "admin"
	RoleOperator   = "operator"
	RoleViewer     = "viewer"
)

// User adalah entity pengguna sistem HAPM
type User struct {
	ID        int        `json:"id_users"`
	Username  string     `json:"username"`
	Email     string     `json:"email"`
	Password  string     `json:"-"` // tidak pernah dikembalikan ke client
	FullName  string     `json:"full_name"`
	Role      string     `json:"role"`
	Active    bool       `json:"active"`
	Locked    bool       `json:"locked"`
	LockUntil *time.Time `json:"lock_until,omitempty"`
	LastLogin *time.Time `json:"last_login,omitempty"`
	Created   time.Time  `json:"created"`
	Timestamp time.Time  `json:"timestamp"`
}

// IsRole memeriksa apakah user memiliki role tertentu
func (u *User) IsRole(role string) bool {
	return u.Role == role
}

// CanManageUsers mengembalikan true jika user boleh mengelola user lain
func (u *User) CanManageUsers() bool {
	return u.Role == RoleSuperAdmin || u.Role == RoleAdmin
}

// CanDeploy mengembalikan true jika user boleh melakukan deploy
func (u *User) CanDeploy() bool {
	return u.Role == RoleSuperAdmin || u.Role == RoleAdmin || u.Role == RoleOperator
}

// CanWrite mengembalikan true jika user boleh melakukan operasi tulis
func (u *User) CanWrite() bool {
	return u.Role != RoleViewer
}

// IsLocked mengembalikan true jika akun sedang dalam status locked
func (u *User) IsLocked() bool {
	if !u.Locked {
		return false
	}
	if u.LockUntil == nil {
		return true // locked indefinitely
	}
	return time.Now().Before(*u.LockUntil)
}

// RefreshToken adalah entity refresh token
type RefreshToken struct {
	ID        int       `json:"id_refresh_tokens"`
	UserID    int       `json:"id_users"`
	TokenHash string    `json:"-"` // SHA256 dari raw token
	JTI       string    `json:"-"` // JWT ID, unique per token
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	UserAgent string    `json:"-"`
	IPAddress string    `json:"-"`
	Created   time.Time `json:"created"`
}

// LoginAttempt adalah entity untuk tracking percobaan login
type LoginAttempt struct {
	ID        int       `json:"id_login_attempts"`
	UserID    *int      `json:"id_users,omitempty"`
	IPAddress string    `json:"ip_address"`
	Username  string    `json:"username"`
	UserAgent string    `json:"user_agent,omitempty"`
	Success   bool      `json:"success"`
	Created   time.Time `json:"created"`
}

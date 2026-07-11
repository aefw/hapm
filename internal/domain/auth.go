package domain

import "time"

// AuthUser adalah user yang dikelola untuk Basic Authentication HAProxy userlist.
// Password disimpan dalam format bcrypt hash ($2b$) — password plaintext tidak pernah tersimpan.
type AuthUser struct {
	ID           int       `json:"id_auth_users"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"` // tidak pernah dikirim ke client
	Description  string    `json:"description"`
	Enabled      bool      `json:"enabled"`
	Created      time.Time `json:"created"`
	Timestamp    time.Time `json:"timestamp"`
}

// AuthGroup adalah grup user untuk HAProxy userlist.
// Satu group dapat di-assign ke satu atau lebih domain/service untuk Basic Authentication.
type AuthGroup struct {
	ID          int         `json:"id_auth_groups"`
	GroupName   string      `json:"group_name"`
	Description string      `json:"description"`
	Enabled     bool        `json:"enabled"`
	Members     []*AuthUser `json:"members,omitempty"`
	Created     time.Time   `json:"created"`
	Timestamp   time.Time   `json:"timestamp"`
}

// AuthGroupMember adalah relasi antara AuthGroup dan AuthUser.
type AuthGroupMember struct {
	ID          int       `json:"id_auth_group_users"`
	AuthGroupID int       `json:"id_auth_groups"`
	AuthUserID  int       `json:"id_auth_users"`
	User        *AuthUser `json:"user,omitempty"`
	Created     time.Time `json:"created"`
}

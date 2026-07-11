package domain

import "time"

// ConfigRevision adalah entity revisi konfigurasi HAProxy
type ConfigRevision struct {
	ID             int       `json:"id_config_revisions"`
	NodeID         int       `json:"id_nodes"`
	RevisionNumber int       `json:"revision_number"`
	ConfigContent  string    `json:"config_content"`
	Comment        string    `json:"comment"`
	UserID         int       `json:"id_users"`
	Username       string    `json:"username,omitempty"` // join dari users
	Deployed       bool      `json:"deployed"`
	Created        time.Time `json:"created"`
	Timestamp      time.Time `json:"timestamp"`
}

// ConfigRevisionSummary adalah versi ringkas tanpa config_content penuh
type ConfigRevisionSummary struct {
	ID             int       `json:"id_config_revisions"`
	NodeID         int       `json:"id_nodes"`
	RevisionNumber int       `json:"revision_number"`
	Comment        string    `json:"comment"`
	UserID         int       `json:"id_users"`
	Username       string    `json:"username,omitempty"`
	Deployed       bool      `json:"deployed"`
	Created        time.Time `json:"created"`
}

// ConfigDiff adalah hasil diff antara dua revisi konfigurasi
type ConfigDiff struct {
	FromRevision int    `json:"from_revision"`
	ToRevision   int    `json:"to_revision"`
	Diff         string `json:"diff"` // unified diff format
}

package domain

import "time"

// ReplicationTarget mendefinisikan relasi push replication antar node
type ReplicationTarget struct {
	ID             int       `json:"id_replication_targets"`
	SourceNodeID   int       `json:"id_nodes_source"`
	SourceNodeName string    `json:"source_node_name,omitempty"`
	TargetNodeID   int       `json:"id_nodes_target"`
	TargetNodeName string    `json:"target_node_name,omitempty"`
	SyncFrontends  bool      `json:"sync_frontends"`
	SyncBackends   bool      `json:"sync_backends"`
	SyncSSL        bool      `json:"sync_ssl"`
	SyncMaps       bool      `json:"sync_maps"`
	Enabled        bool      `json:"enabled"`
	Created        time.Time `json:"created"`
	Timestamp      time.Time `json:"timestamp"`
}

// ReplicationJob adalah record eksekusi replication
type ReplicationJob struct {
	ID               int        `json:"id_replication_jobs"`
	ReplicationID    int        `json:"id_replication_targets"`
	UserID           *int       `json:"id_users,omitempty"`
	Username         string     `json:"username,omitempty"`
	Status           string     `json:"status"` // pending|running|success|failed
	ErrorMessage     string     `json:"error_message,omitempty"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	Created          time.Time  `json:"created"`
}

// DriftReport adalah laporan perbandingan konfigurasi live vs database
type DriftReport struct {
	ID             int       `json:"id_drift_reports"`
	NodeID         int       `json:"id_nodes"`
	NodeName       string    `json:"node_name,omitempty"`
	LiveConfigHash string    `json:"live_config_hash"`
	DBConfigHash   string    `json:"db_config_hash"`
	DriftDetected  bool      `json:"drift_detected"`
	CheckedAt      time.Time `json:"checked_at"`
	Created        time.Time `json:"created"`
}

package domain

import "time"

// DeployStatus adalah status deployment
type DeployStatus string

const (
	DeployStatusPending    DeployStatus = "pending"
	DeployStatusRunning    DeployStatus = "running"
	DeployStatusSuccess    DeployStatus = "success"
	DeployStatusFailed     DeployStatus = "failed"
	DeployStatusRolledBack DeployStatus = "rolled_back"
)

// DeployStage adalah tahap deployment
type DeployStage string

const (
	DeployStageGenerate DeployStage = "generate"
	DeployStageValidate DeployStage = "validate"
	DeployStageBackup   DeployStage = "backup"
	DeployStageUpload   DeployStage = "upload"
	DeployStageReload   DeployStage = "reload"
	DeployStageVerify   DeployStage = "verify"
	DeployStageRollback DeployStage = "rollback"
)

// Deployment adalah entity record deployment
type Deployment struct {
	ID               int          `json:"id_deployments"`
	NodeID           int          `json:"id_nodes"`
	NodeName         string       `json:"node_name,omitempty"` // join dari nodes
	RevisionID       int          `json:"id_config_revisions"`
	RevisionNumber   int          `json:"revision_number,omitempty"` // join dari revisions
	UserID           int          `json:"id_users"`
	Username         string       `json:"username,omitempty"` // join dari users
	Status           DeployStatus `json:"status"`
	Stage            DeployStage  `json:"stage,omitempty"`
	ErrorMessage     string       `json:"error_message,omitempty"`
	StartedAt        *time.Time   `json:"started_at,omitempty"`
	FinishedAt       *time.Time   `json:"finished_at,omitempty"`
	Created          time.Time    `json:"created"`
	Timestamp        time.Time    `json:"timestamp"`
}

// DeployRequest adalah request untuk memulai deployment
type DeployRequest struct {
	NodeID  int    `json:"id_nodes"`
	Comment string `json:"comment"`
	UserID  int    `json:"-"` // diisi dari JWT claims
}

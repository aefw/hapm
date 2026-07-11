package domain

import "time"

// AuditLog adalah entity audit trail aktivitas sistem
type AuditLog struct {
	ID           int       `json:"id_audit_logs"`
	UserID       *int      `json:"id_users,omitempty"`
	Username     string    `json:"username,omitempty"` // join dari users
	Action       string    `json:"action"`             // e.g. "user.login", "node.create"
	ResourceType string    `json:"resource_type,omitempty"`
	ResourceID   *int      `json:"resource_id,omitempty"`
	Detail       string    `json:"detail,omitempty"` // JSON string
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Created      time.Time `json:"created"`
}

// Aksi audit yang digunakan di seluruh sistem
const (
	// Auth
	AuditActionUserLogin          = "user.login"
	AuditActionUserLogout         = "user.logout"
	AuditActionUserLoginFailed    = "user.login.failed"
	AuditActionUserLocked         = "user.locked"
	AuditActionPasswordChanged    = "user.password.changed"
	AuditActionTokenRefreshed     = "user.token.refreshed"

	// User Management
	AuditActionUserCreated        = "user.created"
	AuditActionUserUpdated        = "user.updated"
	AuditActionUserDeleted        = "user.deleted"

	// Node
	AuditActionNodeCreated        = "node.created"
	AuditActionNodeUpdated        = "node.updated"
	AuditActionNodeDeleted        = "node.deleted"
	AuditActionNodeTested         = "node.tested"
	AuditActionNodeProvisioned    = "node.provisioned"

	// Backend
	AuditActionBackendCreated          = "backend.created"
	AuditActionBackendUpdated          = "backend.updated"
	AuditActionBackendDeleted          = "backend.deleted"
	AuditActionBackendHealthCheckChanged = "backend.health_check.changed"

	// Domain
	AuditActionDomainCreated      = "domain.created"
	AuditActionDomainUpdated      = "domain.updated"
	AuditActionDomainDeleted      = "domain.deleted"

	// Certificate Management Center (CMC)
	AuditActionCertCreated    = "cert.created"
	AuditActionCertUploaded   = "cert.uploaded"
	AuditActionCertUpdated    = "cert.updated"
	AuditActionCertDeleted    = "cert.deleted"
	AuditActionCertIssued     = "cert.issued"
	AuditActionCertRenewed    = "cert.renewed"
	AuditActionCertRevoked    = "cert.revoked"
	AuditActionCertDeployed   = "cert.deployed"
	AuditActionCertIssueFailed = "cert.issue.failed"
	AuditActionCertRenewFailed = "cert.renew.failed"
	AuditActionSettingUpdated = "setting.updated"

	// Deploy
	AuditActionDeployStarted      = "deploy.started"
	AuditActionDeploySuccess      = "deploy.success"
	AuditActionDeployFailed       = "deploy.failed"
	AuditActionDeployRolledBack   = "deploy.rolled_back"

	// Replication
	AuditActionReplicationPushed  = "replication.pushed"
	AuditActionReplicationFailed  = "replication.failed"

	// Revision
	AuditActionRevisionRestored = "revision.restored"

	// Service
	AuditActionServiceCreated = "service.created"
	AuditActionServiceUpdated = "service.updated"
	AuditActionServiceDeleted = "service.deleted"
)

// AuditFilter adalah filter untuk query audit log
type AuditFilter struct {
	Q            string     // keyword pencarian pada action, resource_type, detail
	UserID       *int
	Action       string
	ResourceType string
	ResourceID   *int
	FromDate     *time.Time
	ToDate       *time.Time
	Limit        int
	Start        int // offset (0-based)
}

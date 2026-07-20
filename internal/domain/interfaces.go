package domain

import (
	"context"
	"net/http"
)

// ─────────────────────────────────────────────────────────────────────────────
// REPOSITORY INTERFACES
// Didefinisikan di domain agar service tidak bergantung pada implementasi DB.
// ─────────────────────────────────────────────────────────────────────────────

// UserRepository mendefinisikan kontrak akses data User
type UserRepository interface {
	FindByID(ctx context.Context, id int) (*User, error)
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	List(ctx context.Context, filter ListFilter) ([]*User, int, error)
	Create(ctx context.Context, u *User) (int, error)
	Update(ctx context.Context, u *User) error
	UpdatePassword(ctx context.Context, userID int, passwordHash string) error
	Delete(ctx context.Context, id int) error
	UpdateLastLogin(ctx context.Context, id int) error
	SetLocked(ctx context.Context, id int, locked bool, lockUntil any) error
}

// RefreshTokenRepository mendefinisikan kontrak akses data RefreshToken
type RefreshTokenRepository interface {
	Create(ctx context.Context, rt *RefreshToken) error
	FindByTokenHash(ctx context.Context, hash string) (*RefreshToken, error)
	Revoke(ctx context.Context, id int) error
	RevokeAllByUser(ctx context.Context, userID int) error
	DeleteExpired(ctx context.Context) error
}

// LoginAttemptRepository mendefinisikan kontrak akses data LoginAttempt
type LoginAttemptRepository interface {
	Create(ctx context.Context, la *LoginAttempt) error
	CountFailedByIP(ctx context.Context, ip string, windowMinutes int) (int, error)
	CountFailedByUsername(ctx context.Context, username string, windowMinutes int) (int, error)
}

// NodeRepository mendefinisikan kontrak akses data Node
type NodeRepository interface {
	FindByID(ctx context.Context, id int) (*Node, error)
	FindByName(ctx context.Context, name string) (*Node, error)
	List(ctx context.Context, filter ListFilter) ([]*Node, int, error)
	Create(ctx context.Context, n *Node) (int, error)
	Update(ctx context.Context, n *Node) error
	Delete(ctx context.Context, id int) error
	UpdateStatus(ctx context.Context, id int, status NodeStatus, version string) error
	// UpdateProvisionProgress memperbarui step dan pesan error proses provision.
	// step: 0=idle/reset, 1-6=sedang berjalan atau gagal, 7=selesai.
	// errMsg kosong berarti step berhasil; non-kosong berarti gagal pada step tersebut.
	UpdateProvisionProgress(ctx context.Context, id int, step int, errMsg string) error
}

// BackendRepository mendefinisikan kontrak akses data BackendPool dan BackendServer
type BackendRepository interface {
	// Pool
	FindPoolByID(ctx context.Context, id int) (*BackendPool, error)
	FindPoolByName(ctx context.Context, name string) (*BackendPool, error)
	ListPools(ctx context.Context, filter ListFilter) ([]*BackendPool, int, error)
	CreatePool(ctx context.Context, p *BackendPool) (int, error)
	CreatePoolWithServers(ctx context.Context, p *BackendPool, servers []*BackendServer) (int, error)
	UpdatePool(ctx context.Context, p *BackendPool) error
	DeletePool(ctx context.Context, id int) error

	// Server
	ReplaceServers(ctx context.Context, poolID int, servers []*BackendServer) error
}

// DomainRepository mendefinisikan kontrak akses data DomainEntry
type DomainRepository interface {
	FindByID(ctx context.Context, id int) (*DomainEntry, error)
	FindByDomainName(ctx context.Context, name string) (*DomainEntry, error)
	List(ctx context.Context, filter ListFilter) ([]*DomainEntry, int, error)
	ListEnabled(ctx context.Context) ([]*DomainEntry, error)
	Create(ctx context.Context, d *DomainEntry) (int, error)
	Update(ctx context.Context, d *DomainEntry) error
	Delete(ctx context.Context, id int) error
}

// CertificateRepository mendefinisikan kontrak akses data Certificate (CMC)
type CertificateRepository interface {
	FindByUUID(ctx context.Context, uuid string) (*Certificate, error)
	FindByName(ctx context.Context, name string) (*Certificate, error)
	List(ctx context.Context, filter ListFilter) ([]*Certificate, int, error)
	ListNeedingRenewal(ctx context.Context) ([]*Certificate, error)
	ListByStatus(ctx context.Context, status CertStatus) ([]*Certificate, error)
	Create(ctx context.Context, c *Certificate) error
	Update(ctx context.Context, c *Certificate) error
	Delete(ctx context.Context, uuid string) error
	Lock(ctx context.Context, uuid string) (bool, error)
	Unlock(ctx context.Context, uuid string) error
}

// CertJobRepository mendefinisikan kontrak akses data CertJob
type CertJobRepository interface {
	FindByUUID(ctx context.Context, uuid string) (*CertJob, error)
	ListByCert(ctx context.Context, certUUID string, limit int) ([]*CertJob, error)
	ListAll(ctx context.Context, limit int) ([]*CertJob, error)
	Create(ctx context.Context, j *CertJob) error
	UpdateStatus(ctx context.Context, uuid, status, logs, errMsg string) error
}

// CertDeploymentRepository mendefinisikan kontrak akses data CertDeployment
type CertDeploymentRepository interface {
	FindByUUID(ctx context.Context, uuid string) (*CertDeployment, error)
	ListByCert(ctx context.Context, certUUID string) ([]*CertDeployment, error)
	ListRecentFailed(ctx context.Context, days int) ([]*CertDeployment, error)
	Create(ctx context.Context, d *CertDeployment) error
	UpdateStatus(ctx context.Context, uuid, status, errMsg string) error
}

// SettingRepository mendefinisikan kontrak akses data Setting
type SettingRepository interface {
	Get(ctx context.Context, key string) (*Setting, error)
	Set(ctx context.Context, key, value string, encrypted bool) error
	Delete(ctx context.Context, key string) error
}

// ErrorPageRepository mendefinisikan kontrak akses data ErrorPage
type ErrorPageRepository interface {
	List(ctx context.Context) ([]*ErrorPage, error)
	FindByCode(ctx context.Context, code int) (*ErrorPage, error)
	Update(ctx context.Context, ep *ErrorPage) error
}

// RevisionRepository mendefinisikan kontrak akses data ConfigRevision
type RevisionRepository interface {
	FindByID(ctx context.Context, id int) (*ConfigRevision, error)
	FindByNodeAndNumber(ctx context.Context, nodeID, number int) (*ConfigRevision, error)
	LatestByNode(ctx context.Context, nodeID int) (*ConfigRevision, error)
	ListByNode(ctx context.Context, nodeID int) ([]*ConfigRevisionSummary, error)
	Create(ctx context.Context, r *ConfigRevision) (int, error)
	MarkDeployed(ctx context.Context, id int) error
	NextRevisionNumber(ctx context.Context, nodeID int) (int, error)
}

// DeploymentRepository mendefinisikan kontrak akses data Deployment
type DeploymentRepository interface {
	FindByID(ctx context.Context, id int) (*Deployment, error)
	ListByNode(ctx context.Context, nodeID int, limit int) ([]*Deployment, error)
	ListRecent(ctx context.Context, limit int) ([]*Deployment, error)
	Create(ctx context.Context, d *Deployment) (int, error)
	UpdateStatus(ctx context.Context, id int, status DeployStatus, stage DeployStage, errMsg string) error
}

// ReplicationRepository mendefinisikan kontrak akses data Replication
type ReplicationRepository interface {
	FindTargetByID(ctx context.Context, id int) (*ReplicationTarget, error)
	ListTargets(ctx context.Context) ([]*ReplicationTarget, error)
	ListTargetsBySource(ctx context.Context, sourceNodeID int) ([]*ReplicationTarget, error)
	CreateTarget(ctx context.Context, t *ReplicationTarget) (int, error)
	UpdateTarget(ctx context.Context, t *ReplicationTarget) error
	DeleteTarget(ctx context.Context, id int) error

	CreateJob(ctx context.Context, j *ReplicationJob) (int, error)
	UpdateJobStatus(ctx context.Context, id int, status string, errMsg string) error
}

// DriftRepository mendefinisikan kontrak akses data DriftReport
type DriftRepository interface {
	Create(ctx context.Context, r *DriftReport) (int, error)
	LatestByNode(ctx context.Context, nodeID int) (*DriftReport, error)
	ListRecent(ctx context.Context, limit int) ([]*DriftReport, error)
}

// AuditRepository mendefinisikan kontrak akses data AuditLog
type AuditRepository interface {
	Create(ctx context.Context, log *AuditLog) error
	List(ctx context.Context, filter AuditFilter) ([]*AuditLog, int, error)
	FindByID(ctx context.Context, id int) (*AuditLog, error)
}

// AuthUserRepository mendefinisikan kontrak akses data AuthUser
type AuthUserRepository interface {
	FindByID(ctx context.Context, id int) (*AuthUser, error)
	FindByUsername(ctx context.Context, username string) (*AuthUser, error)
	List(ctx context.Context, filter ListFilter) ([]*AuthUser, int, error)
	Create(ctx context.Context, u *AuthUser) (int, error)
	Update(ctx context.Context, u *AuthUser) error
	Delete(ctx context.Context, id int) error
}

// AuthGroupRepository mendefinisikan kontrak akses data AuthGroup
type AuthGroupRepository interface {
	FindByID(ctx context.Context, id int) (*AuthGroup, error)
	FindByName(ctx context.Context, name string) (*AuthGroup, error)
	List(ctx context.Context, filter ListFilter) ([]*AuthGroup, int, error)
	ListEnabled(ctx context.Context) ([]*AuthGroup, error) // untuk config generator — semua enabled dengan members
	Create(ctx context.Context, g *AuthGroup) (int, error)
	Update(ctx context.Context, g *AuthGroup) error
	Delete(ctx context.Context, id int) error

	// Members
	AddMember(ctx context.Context, groupID, userID int) error
	RemoveMember(ctx context.Context, groupID, userID int) error
	ListMembers(ctx context.Context, groupID int) ([]*AuthUser, error)
	IsMember(ctx context.Context, groupID, userID int) (bool, error)
}

// ServiceRepository mendefinisikan kontrak akses data Service
type ServiceRepository interface {
	FindByID(ctx context.Context, id int) (*Service, error)
	FindByName(ctx context.Context, name string) (*Service, error)
	FindByPort(ctx context.Context, port int) (*Service, error)
	List(ctx context.Context, filter ListFilter) ([]*Service, int, error)
	ListEnabled(ctx context.Context) ([]*Service, error)
	Create(ctx context.Context, s *Service) (int, error)
	Update(ctx context.Context, s *Service) error
	Delete(ctx context.Context, id int) error
}

// ─────────────────────────────────────────────────────────────────────────────
// SERVICE INTERFACES
// ─────────────────────────────────────────────────────────────────────────────

// LoginRequest adalah request body untuk endpoint login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse adalah data yang dikembalikan setelah login berhasil
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // detik
	User         *User  `json:"user"`
}

// RefreshRequest adalah request body untuk endpoint refresh token
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse adalah data yang dikembalikan setelah refresh berhasil
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// ChangePasswordRequest adalah request body untuk ganti password
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// AuthService mendefinisikan kontrak layanan autentikasi
type AuthService interface {
	Login(ctx context.Context, r *http.Request, req *LoginRequest) (*LoginResponse, error)
	Logout(ctx context.Context, userID int, refreshToken string) error
	RefreshToken(ctx context.Context, req *RefreshRequest) (*RefreshResponse, error)
	ChangePassword(ctx context.Context, userID int, req *ChangePasswordRequest) error
	GetMe(ctx context.Context, userID int) (*User, error)
}

// CreateUserRequest adalah request untuk membuat user baru
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
}

// UpdateUserRequest adalah request untuk update user
type UpdateUserRequest struct {
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
	Active   *bool  `json:"active"`
}

// UserService mendefinisikan kontrak layanan manajemen user
type UserService interface {
	GetByID(ctx context.Context, id int) (*User, error)
	List(ctx context.Context, filter ListFilter) ([]*User, int, error)
	Create(ctx context.Context, req *CreateUserRequest, actorID int) (*User, error)
	Update(ctx context.Context, id int, req *UpdateUserRequest, actorID int) (*User, error)
	Delete(ctx context.Context, id int, actorID int) error
	SetLocked(ctx context.Context, id int, locked bool, actorID int) error
}

// CreateNodeRequest adalah request untuk membuat node baru
type CreateNodeRequest struct {
	Name                 string `json:"name"`
	Hostname             string `json:"hostname"`
	IPAddress            string `json:"ip_address"`
	SSHPort              int    `json:"ssh_port"`
	SSHUser              string `json:"ssh_user"`
	SSHPrivateKey        string `json:"ssh_private_key"` // plaintext, akan dienkripsi
	Description          string `json:"description"`
	BehindCloudflare     bool   `json:"behind_cloudflare"`
	HTTPSFrontendEnabled bool   `json:"https_frontend_enabled"` // true = selalu generate frontend https_in
}

// UpdateNodeRequest adalah request untuk update node
type UpdateNodeRequest struct {
	Name                 string `json:"name"`
	Hostname             string `json:"hostname"`
	IPAddress            string `json:"ip_address"`
	SSHPort              int    `json:"ssh_port"`
	SSHUser              string `json:"ssh_user"`
	SSHPrivateKey        string `json:"ssh_private_key"` // kosong = tidak diubah
	Description          string `json:"description"`
	BehindCloudflare     bool   `json:"behind_cloudflare"`
	HTTPSFrontendEnabled bool   `json:"https_frontend_enabled"`
	// Statistics page config — disatukan agar cukup 1 request saat simpan node
	StatsEnabled       bool   `json:"stats_enabled"`
	StatsBindAddr      string `json:"stats_bind_addr"`
	StatsPort          int    `json:"stats_port"`
	StatsURI           string `json:"stats_uri"`
	StatsRefresh       string `json:"stats_refresh"`
	StatsHideVersion   bool   `json:"stats_hide_version"`
	StatsReadOnly      bool   `json:"stats_readonly"`
	StatsAdmin         bool   `json:"stats_admin"`
	StatsAllowedGroups []int  `json:"stats_allowed_groups"`
}

// TestConnectionResult adalah hasil test koneksi SSH ke node
type TestConnectionResult struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	HAProxyVersion string `json:"haproxy_version,omitempty"`
	Latency        string `json:"latency,omitempty"`
}

// NodeService mendefinisikan kontrak layanan manajemen node
type NodeService interface {
	GetByID(ctx context.Context, id int) (*Node, error)
	List(ctx context.Context, filter ListFilter) ([]*NodeSummary, int, error)
	Create(ctx context.Context, req *CreateNodeRequest, actorID int) (*Node, error)
	Update(ctx context.Context, id int, req *UpdateNodeRequest, actorID int) (*Node, error)
	Delete(ctx context.Context, id int, actorID int) error
	TestConnection(ctx context.Context, id int) (*TestConnectionResult, error)
	Provision(ctx context.Context, id int, actorID int) error
}

// CreatePoolRequest adalah request untuk membuat/update backend pool.
// Field Servers bersifat opsional:
//   - POST: jika diisi, pool dan server dibuat atomik (rollback jika server error)
//   - PUT:  jika diisi (termasuk array kosong), server lama diganti; jika null, server tidak diubah
type CreatePoolRequest struct {
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Algorithm         Algorithm              `json:"algorithm"`
	TimeoutConnect    int                    `json:"timeout_connect"`
	TimeoutServer     int                    `json:"timeout_server"`
	Protocol          BackendProtocol        `json:"protocol,omitempty"`           // http (default) | https | tcp
	SSLMode           BackendSSLMode         `json:"ssl_mode,omitempty"`           // none (default) | trusted | self_signed; hanya untuk protocol=https
	ForwardHeaders    *bool                  `json:"forward_headers,omitempty"`    // nil = default true (create) / keep (update)
	HealthCheck       bool                   `json:"health_check"`                 // backward compat: true → default HTTP check
	HealthCheckType   string                 `json:"health_check_type,omitempty"`  // overrides HealthCheck bool
	HealthCheckConfig *HealthCheckConfig     `json:"health_check_config,omitempty"`// params untuk health check type
	Servers           *[]CreateServerRequest `json:"servers,omitempty"`            // opsional: buat/ganti server sekaligus
}

// CreateServerRequest adalah request untuk menambah server ke pool
type CreateServerRequest struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
	Port      int    `json:"port"`
	Weight    int    `json:"weight"`
	Backup    bool   `json:"backup"`
	Enabled   bool   `json:"enabled"`
}

// BackendService mendefinisikan kontrak layanan manajemen backend pool
type BackendService interface {
	GetPoolByID(ctx context.Context, id int) (*BackendPool, error)
	ListPools(ctx context.Context, filter ListFilter) ([]*BackendPool, int, error)
	CreatePool(ctx context.Context, req *CreatePoolRequest, actorID int) (*BackendPool, error)
	UpdatePool(ctx context.Context, id int, req *CreatePoolRequest, actorID int) (*BackendPool, error)
	DeletePool(ctx context.Context, id int, actorID int) error
}

// CreateDomainRequest adalah request untuk membuat domain routing
type CreateDomainRequest struct {
	DomainName    string  `json:"domain_name"`
	BackendPoolID int     `json:"id_backend_pools"`
	SSLMode       SSLMode `json:"ssl_mode"`
	CertUUID      *string `json:"cert_uuid,omitempty"`
	AuthGroupID   *int    `json:"id_auth_groups,omitempty"` // nil = tanpa auth
	HTTPRedirect  bool    `json:"http_redirect"`
	Enabled       bool    `json:"enabled"`
	Description   string  `json:"description"`
}

// DomainService mendefinisikan kontrak layanan manajemen domain
type DomainService interface {
	GetByID(ctx context.Context, id int) (*DomainEntry, error)
	List(ctx context.Context, filter ListFilter) ([]*DomainEntry, int, error)
	Create(ctx context.Context, req *CreateDomainRequest, actorID int) (*DomainEntry, error)
	Update(ctx context.Context, id int, req *CreateDomainRequest, actorID int) (*DomainEntry, error)
	Delete(ctx context.Context, id int, actorID int) error
}

// CreateCertRequest adalah request untuk membuat certificate baru (CMC)
type CreateCertRequest struct {
	Name        string          `json:"name"`
	Provider    CertProvider    `json:"provider"`
	Challenge   CertChallenge   `json:"challenge"`
	Domains     []string        `json:"domains"`
	DNSProvider DNSProviderType `json:"dns_provider,omitempty"`
	Zone        string          `json:"zone,omitempty"`
	RenewBefore int             `json:"renew_before"`
	AutoRenew   bool            `json:"auto_renew"`
}

// UploadCertRequest adalah request untuk upload certificate manual (CMC)
type UploadCertRequest struct {
	Name        string `json:"name"`
	CertPEM     string `json:"certificate_pem"`
	KeyPEM      string `json:"private_key_pem"`
	ChainPEM    string `json:"chain_pem,omitempty"`
	AutoRenew   bool   `json:"auto_renew"`
}

// DeployCertRequest adalah request untuk deploy certificate ke node
type DeployCertRequest struct {
	NodeIDs []int `json:"node_ids"`
}

// CloudflareTestResult adalah hasil test koneksi Cloudflare
type CloudflareTestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Email   string `json:"email,omitempty"`
}

// CloudflareZone adalah zone Cloudflare
type CloudflareZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CertificateService mendefinisikan kontrak layanan Certificate Management Center
type CertificateService interface {
	GetByUUID(ctx context.Context, uuid string) (*Certificate, error)
	List(ctx context.Context, filter ListFilter) ([]*Certificate, int, error)
	Create(ctx context.Context, req *CreateCertRequest, actorID int) (*Certificate, error)
	Update(ctx context.Context, uuid string, req *CreateCertRequest, actorID int) (*Certificate, error)
	Upload(ctx context.Context, req *UploadCertRequest, actorID int) (*Certificate, error)
	Delete(ctx context.Context, uuid string, actorID int) error
	Issue(ctx context.Context, uuid string, actorID int) (*CertJob, error)
	Renew(ctx context.Context, uuid string, actorID int) (*CertJob, error)
	Revoke(ctx context.Context, uuid string, actorID int) error
	Deploy(ctx context.Context, uuid string, req *DeployCertRequest, actorID int) ([]*CertJob, error)
}

// CertJobService mendefinisikan kontrak layanan job management
type CertJobService interface {
	GetByUUID(ctx context.Context, uuid string) (*CertJob, error)
	ListByCert(ctx context.Context, certUUID string, limit int) ([]*CertJob, error)
	ListAll(ctx context.Context, limit int) ([]*CertJob, error)
}

// DistributionService mendefinisikan kontrak layanan distribusi certificate ke node
type DistributionService interface {
	Distribute(ctx context.Context, certUUID string, nodeIDs []int, actorID int) ([]*CertDeployment, error)
	DistributeToAll(ctx context.Context, certUUID string, actorID int) ([]*CertDeployment, error)
}

// SchedulerService mendefinisikan kontrak layanan auto-renew scheduler
type SchedulerService interface {
	Start(ctx context.Context)
	Stop()
}

// SettingsService mendefinisikan kontrak layanan settings
type SettingsService interface {
	GetCloudflareToken(ctx context.Context) (string, error)
	SetCloudflareToken(ctx context.Context, token string) error
	TestCloudflareConnection(ctx context.Context) (*CloudflareTestResult, error)
	DiscoverCloudflareZones(ctx context.Context, inputToken string) ([]*CloudflareZone, error)
	GetACMEEmail(ctx context.Context) (string, error)
	SetACMEEmail(ctx context.Context, email string) error
	IsACMEStaging(ctx context.Context) (bool, error)
	SetACMEStaging(ctx context.Context, staging bool) error
	IsCustomErrorPagesEnabled(ctx context.Context) (bool, error)
	SetCustomErrorPagesEnabled(ctx context.Context, enabled bool) error
}

// GeneratedConfig adalah hasil generate konfigurasi HAProxy
type GeneratedConfig struct {
	NodeID     int            `json:"id_nodes"`
	Content    string         `json:"content"`
	HostsMap   string         `json:"hosts_map"`   // content untuk /etc/haproxy/map/hosts
	Hash       string         `json:"hash"`        // SHA256 dari content
	ErrorPages map[int]string `json:"-"`           // code → wrapped HTTP content untuk deploy ke node
}

// ConfigService mendefinisikan kontrak layanan generate konfigurasi
type ConfigService interface {
	GenerateForNode(ctx context.Context, nodeID int) (*GeneratedConfig, error)
	ValidateConfig(ctx context.Context, nodeID int) (bool, string, error)
}

// RevisionService mendefinisikan kontrak layanan manajemen revisi
type RevisionService interface {
	ListByNode(ctx context.Context, nodeID int) ([]*ConfigRevisionSummary, error)
	GetRevision(ctx context.Context, nodeID, revNumber int) (*ConfigRevision, error)
	Diff(ctx context.Context, nodeID, revNumber int) (*ConfigDiff, error)
	Restore(ctx context.Context, nodeID, revNumber int, actorID int) error
}

// DeployService mendefinisikan kontrak layanan deployment
type DeployService interface {
	Deploy(ctx context.Context, req *DeployRequest) (*Deployment, error)
	GetStatus(ctx context.Context, deployID int) (*Deployment, error)
	ListByNode(ctx context.Context, nodeID int, limit int) ([]*Deployment, error)
}

// CreateReplicationTargetRequest adalah request untuk membuat replication target
type CreateReplicationTargetRequest struct {
	SourceNodeID  int  `json:"id_nodes_source"`
	TargetNodeID  int  `json:"id_nodes_target"`
	SyncFrontends bool `json:"sync_frontends"`
	SyncBackends  bool `json:"sync_backends"`
	SyncSSL       bool `json:"sync_ssl"`
	SyncMaps      bool `json:"sync_maps"`
	Enabled       bool `json:"enabled"`
}

// ReplicationService mendefinisikan kontrak layanan replication
type ReplicationService interface {
	ListTargets(ctx context.Context) ([]*ReplicationTarget, error)
	CreateTarget(ctx context.Context, req *CreateReplicationTargetRequest, actorID int) (*ReplicationTarget, error)
	UpdateTarget(ctx context.Context, id int, req *CreateReplicationTargetRequest, actorID int) (*ReplicationTarget, error)
	DeleteTarget(ctx context.Context, id int, actorID int) error
	PushReplication(ctx context.Context, targetID int, actorID int) (*ReplicationJob, error)
	CheckDrift(ctx context.Context) ([]*DriftReport, error)
}

// NodeStats adalah statistik HAProxy untuk satu node
type NodeStats struct {
	NodeID    int              `json:"id_nodes"`
	NodeName  string           `json:"node_name"`
	Frontends []*FrontendStats `json:"frontends"`
	Backends  []*BackendStats  `json:"backends"`
}

// FrontendStats adalah statistik frontend HAProxy
type FrontendStats struct {
	Name            string `json:"name"`
	Status          string `json:"status"`
	CurrentSessions int64  `json:"current_sessions"`
	TotalSessions   int64  `json:"total_sessions"`
	BytesIn         int64  `json:"bytes_in"`
	BytesOut        int64  `json:"bytes_out"`
	RequestRate     int64  `json:"request_rate"`
}

// BackendStats adalah statistik backend HAProxy
type BackendStats struct {
	Name            string        `json:"name"`
	Status          string        `json:"status"`
	CurrentSessions int64         `json:"current_sessions"`
	TotalSessions   int64         `json:"total_sessions"`
	BytesIn         int64         `json:"bytes_in"`
	BytesOut        int64         `json:"bytes_out"`
	Servers         []*ServerStat `json:"servers"`
}

// ServerStat adalah statistik satu server dalam backend
type ServerStat struct {
	Name            string `json:"name"`
	Address         string `json:"address"`
	Status          string `json:"status"`
	CurrentSessions int64  `json:"current_sessions"`
	TotalSessions   int64  `json:"total_sessions"`
	Weight          int    `json:"weight"`
}

// MonitoringService mendefinisikan kontrak layanan monitoring
type MonitoringService interface {
	GetNodeStats(ctx context.Context, nodeID int) (*NodeStats, error)
	GetFrontendStats(ctx context.Context, nodeID int) ([]*FrontendStats, error)
	GetBackendStats(ctx context.Context, nodeID int) ([]*BackendStats, error)
}

// DashboardService mendefinisikan kontrak layanan dashboard
type DashboardService interface {
	// GetOverview mengambil ringkasan seluruh sistem dari DB (cepat, tanpa SSH)
	GetOverview(ctx context.Context) (*DashboardData, error)
	// GetAllNodeStats mengambil live stats dari semua node secara paralel via SSH
	GetAllNodeStats(ctx context.Context) ([]*DashboardNodeStats, error)
}

// CreateServiceRequest adalah request untuk membuat atau memperbarui service HAProxy
type CreateServiceRequest struct {
	Name          string      `json:"name"`
	ServiceType   ServiceType `json:"service_type"`
	ListenPort    int         `json:"listen_port"`
	BackendPoolID int         `json:"id_backend_pools"`
	Description   string      `json:"description"`
	Enabled       bool        `json:"enabled"`
}

// ServiceService mendefinisikan kontrak layanan manajemen service HAProxy
type ServiceService interface {
	GetByID(ctx context.Context, id int) (*Service, error)
	List(ctx context.Context, filter ListFilter) ([]*Service, int, error)
	Create(ctx context.Context, req *CreateServiceRequest, actorID int) (*Service, error)
	Update(ctx context.Context, id int, req *CreateServiceRequest, actorID int) (*Service, error)
	Delete(ctx context.Context, id int, actorID int) error
}

// CreateAuthUserRequest adalah request untuk membuat/update auth user
type CreateAuthUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"` // wajib saat create, kosong = tidak ubah saat update
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// AuthUserService mendefinisikan kontrak layanan manajemen auth user (HAProxy userlist)
type AuthUserService interface {
	GetByID(ctx context.Context, id int) (*AuthUser, error)
	List(ctx context.Context, filter ListFilter) ([]*AuthUser, int, error)
	Create(ctx context.Context, req *CreateAuthUserRequest, actorID int) (*AuthUser, error)
	Update(ctx context.Context, id int, req *CreateAuthUserRequest, actorID int) (*AuthUser, error)
	Delete(ctx context.Context, id int, actorID int) error
}

// CreateAuthGroupRequest adalah request untuk membuat/update auth group
type CreateAuthGroupRequest struct {
	GroupName   string `json:"group_name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// AddGroupMemberRequest adalah request untuk menambah member ke group
type AddGroupMemberRequest struct {
	AuthUserID int `json:"id_auth_users"`
}

// AuthGroupService mendefinisikan kontrak layanan manajemen auth group (HAProxy userlist)
type AuthGroupService interface {
	GetByID(ctx context.Context, id int) (*AuthGroup, error)
	List(ctx context.Context, filter ListFilter) ([]*AuthGroup, int, error)
	Create(ctx context.Context, req *CreateAuthGroupRequest, actorID int) (*AuthGroup, error)
	Update(ctx context.Context, id int, req *CreateAuthGroupRequest, actorID int) (*AuthGroup, error)
	Delete(ctx context.Context, id int, actorID int) error
	ListMembers(ctx context.Context, groupID int) ([]*AuthUser, error)
	AddMember(ctx context.Context, groupID int, req *AddGroupMemberRequest, actorID int) error
	RemoveMember(ctx context.Context, groupID, userID int, actorID int) error
}

// AuditService mendefinisikan kontrak layanan audit log
type AuditService interface {
	Log(ctx context.Context, log *AuditLog) error
	LogFromRequest(ctx context.Context, r *http.Request, userID *int, action, resourceType string, resourceID *int, detail string) error
	List(ctx context.Context, filter AuditFilter) ([]*AuditLog, int, error)
	GetByID(ctx context.Context, id int) (*AuditLog, error)
}

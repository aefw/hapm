package domain

import "time"

// CertStatus adalah status lifecycle certificate
type CertStatus string

const (
	CertStatusPending  CertStatus = "pending"
	CertStatusIssuing  CertStatus = "issuing"
	CertStatusActive   CertStatus = "active"
	CertStatusExpired  CertStatus = "expired"
	CertStatusRevoked  CertStatus = "revoked"
	CertStatusError    CertStatus = "error"
)

// CertProvider adalah sumber certificate
type CertProvider string

const (
	CertProviderLetsEncrypt CertProvider = "letsencrypt"
	CertProviderManual      CertProvider = "manual"
)

// CertChallenge adalah tipe ACME challenge
type CertChallenge string

const (
	CertChallengeDNS01  CertChallenge = "dns01"
	CertChallengeHTTP01 CertChallenge = "http01"
	CertChallengeNone   CertChallenge = "none"
)

// DNSProviderType adalah provider DNS yang didukung
type DNSProviderType string

const (
	DNSProviderTypeCloudflare DNSProviderType = "cloudflare"
)

// Certificate adalah entity certificate dalam Certificate Management Center
type Certificate struct {
	UUID         string        `json:"uuid"`
	Name         string        `json:"name"`
	Provider     CertProvider  `json:"provider"`
	Challenge    CertChallenge `json:"challenge"`
	Status       CertStatus    `json:"status"`
	Domains      []string      `json:"domains"`
	PrimaryDomain string       `json:"primary_domain"`
	SAN          []string      `json:"san"`
	Zone         string        `json:"zone,omitempty"`
	DNSProvider  DNSProviderType `json:"dns_provider,omitempty"`
	IssuedAt     *time.Time    `json:"issued_at,omitempty"`
	ExpiresAt    *time.Time    `json:"expires_at,omitempty"`
	RenewBefore  int           `json:"renew_before"`
	AutoRenew    bool          `json:"auto_renew"`
	Fingerprint  string        `json:"fingerprint,omitempty"`
	ErrorMessage string        `json:"error_message,omitempty"`
	Created      time.Time     `json:"created"`
	Timestamp    time.Time     `json:"timestamp"`
}

// IsExpired mengembalikan true jika certificate sudah expired
func (c *Certificate) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// DaysUntilExpiry mengembalikan jumlah hari hingga expired. -1 jika tidak diketahui.
func (c *Certificate) DaysUntilExpiry() int {
	if c.ExpiresAt == nil {
		return -1
	}
	return int(time.Until(*c.ExpiresAt).Hours() / 24)
}

// NeedsRenewal mengembalikan true jika certificate perlu diperpanjang
func (c *Certificate) NeedsRenewal() bool {
	if c.ExpiresAt == nil || !c.AutoRenew {
		return false
	}
	days := c.DaysUntilExpiry()
	if days < 0 {
		return true
	}
	renewBefore := c.RenewBefore
	if renewBefore <= 0 {
		renewBefore = 30
	}
	return days <= renewBefore
}

// CertJob adalah entity ACME job (issue, renew, revoke, deploy)
type CertJob struct {
	UUID        string     `json:"uuid"`
	CertUUID    string     `json:"cert_uuid"`
	JobType     string     `json:"job_type"`
	Status      string     `json:"status"`
	Logs        string     `json:"logs,omitempty"`
	ErrorMsg    string     `json:"error_message,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Created     time.Time  `json:"created"`
	Timestamp   time.Time  `json:"timestamp"`
}

const (
	JobTypeIssue  = "issue"
	JobTypeRenew  = "renew"
	JobTypeRevoke = "revoke"
	JobTypeDeploy = "deploy"

	JobStatusPending = "pending"
	JobStatusRunning = "running"
	JobStatusSuccess = "success"
	JobStatusFailed  = "failed"
)

// CertDeployment adalah entity deployment certificate ke HAProxy node
type CertDeployment struct {
	UUID        string     `json:"uuid"`
	CertUUID    string     `json:"cert_uuid"`
	NodeID      int        `json:"id_nodes"`
	NodeName    string     `json:"node_name,omitempty"`
	Status      string     `json:"status"`
	ErrorMsg    string     `json:"error_message,omitempty"`
	DeployedAt  *time.Time `json:"deployed_at,omitempty"`
	Created     time.Time  `json:"created"`
	Timestamp   time.Time  `json:"timestamp"`
}

// Setting adalah entity konfigurasi global HAPM
type Setting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value,omitempty"`
	Encrypted bool      `json:"encrypted"`
	Created   time.Time `json:"created"`
	Timestamp time.Time `json:"timestamp"`
}

const (
	SettingCFAPIToken        = "cloudflare.api_token"
	SettingACMEEmail         = "acme.email"
	SettingACMEStaging       = "acme.staging"
	SettingCustomErrorPages  = "features.custom_error_pages"
)

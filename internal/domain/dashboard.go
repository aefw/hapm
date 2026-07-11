package domain

import "time"

// DashboardNodeSummary adalah ringkasan satu node untuk dashboard overview
type DashboardNodeSummary struct {
	ID             int        `json:"id_nodes"`
	Name           string     `json:"name"`
	IPAddress      string     `json:"ip_address"`
	Status         NodeStatus `json:"status"`
	HAProxyVersion string     `json:"haproxy_version,omitempty"`
	LastChecked    *time.Time `json:"last_checked,omitempty"`
	LastDeployment *DashboardDeployInfo `json:"last_deployment,omitempty"`
}

// DashboardDeployInfo adalah info ringkas deployment terakhir per node
type DashboardDeployInfo struct {
	ID         int          `json:"id_deployments"`
	Status     DeployStatus `json:"status"`
	Stage      DeployStage  `json:"stage"`
	FinishedAt *time.Time   `json:"finished_at,omitempty"`
	Username   string       `json:"username"`
}

// DashboardNodeCount adalah hitungan node per status
type DashboardNodeCount struct {
	Total   int `json:"total"`
	Online  int `json:"online"`
	Offline int `json:"offline"`
	Unknown int `json:"unknown"`
}

// DashboardSummary adalah ringkasan seluruh sistem
type DashboardSummary struct {
	Nodes    DashboardNodeCount `json:"nodes"`
	Domains  int                `json:"domains"`
	Backends int                `json:"backends"`
	Services int                `json:"services"`
	SSLCerts int                `json:"ssl_certs"`
}

// DashboardData adalah response utama GET /api/v1/dashboard
type DashboardData struct {
	Summary           DashboardSummary       `json:"summary"`
	Nodes             []*DashboardNodeSummary `json:"nodes"`
	RecentDeployments []*Deployment           `json:"recent_deployments"`
	RecentAudit       []*AuditLog             `json:"recent_audit"`
}

// DashboardNodeStats adalah live stats satu node untuk GET /api/v1/dashboard/nodes/stats
type DashboardNodeStats struct {
	NodeID    int        `json:"id_nodes"`
	NodeName  string     `json:"node_name"`
	IPAddress string     `json:"ip_address"`
	Status    NodeStatus `json:"status"`
	Error     string     `json:"error,omitempty"`
	Stats     *NodeStats `json:"stats,omitempty"`
}

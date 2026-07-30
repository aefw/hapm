package domain

import "time"

// WAFRule adalah aturan Web Application Firewall yang diterapkan ke HAProxy ACL
type WAFRule struct {
	ID        int       `json:"id_waf_rules"`
	Name      string    `json:"name"`
	RuleType  string    `json:"rule_type"` // ip_block, path_block, ua_block, header_block
	Value     string    `json:"value"`
	Action    string    `json:"action"` // deny, allow
	Enabled   bool      `json:"enabled"`
	DomainIDs []int     `json:"domain_ids"` // kosong = berlaku global semua domain
	Created   time.Time `json:"created"`
	Timestamp time.Time `json:"timestamp"`
}

// WAFRuleTypes adalah daftar tipe rule yang didukung
var WAFRuleTypes = []string{"ip_block", "path_block", "ua_block", "header_block"}

// WAFActions adalah daftar aksi yang didukung
var WAFActions = []string{"deny", "allow"}

// WAFConfig adalah agregat semua WAF data untuk config generation HAProxy.
// Di-load sekali oleh WAFGenerationRepository sebelum GenerateForNode.
type WAFConfig struct {
	Rules       []*WAFRule
	Blacklist   []*WAFBlacklist
	Whitelist   []*WAFWhitelist
	RateLimits  []*WAFRateLimit
	CORSRules   []*WAFCORSRule
	// DomainNames: id_domains → domain_name, untuk generate ACL domain-scoped
	DomainNames map[int]string
}

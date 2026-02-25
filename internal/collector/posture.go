// Package collector provides Okta organization posture collection functionality.
package collector

import "time"

// SchemaVersion is the version of the output schema.
const SchemaVersion = "1.0.0"

// InactiveDaysThreshold is the number of days after which a user is considered inactive.
const InactiveDaysThreshold = 90

// Config holds the collector configuration passed via stdin.
type Config struct {
	OrgDomain  string `json:"org_domain"`  // e.g., "company.okta.com"
	ClientID   string `json:"client_id"`   // OAuth 2.0 client ID
	PrivateKey string `json:"private_key"` // Private key for JWT assertion (PEM)
	APIToken   string `json:"api_token"`   // SSWS token (legacy, less secure)
}

// OrgPosture represents the collected security posture of an Okta organization.
type OrgPosture struct {
	SchemaVersion string       `json:"schema_version"`
	CollectedAt   string       `json:"collected_at"`
	OrgDomain     string       `json:"org_domain"`
	Posture       Posture      `json:"posture"`
	Users         UserMetrics  `json:"users"`
	Apps          AppMetrics   `json:"apps"`
	Policy        PolicyConfig `json:"policy"`
}

// Posture contains high-level security posture scores (all percentages 0-100).
type Posture struct {
	MFACoverage          int `json:"mfa_coverage"`           // % users with any MFA enrolled
	MFAPhishingResistant int `json:"mfa_phishing_resistant"` // % users with WebAuthn/FIDO2
	SSOCoverage          int `json:"sso_coverage"`           // % apps using SSO (SAML/OIDC/WS-Fed)
}

// UserMetrics contains user status percentages (all 0-100).
type UserMetrics struct {
	PasswordExpired int `json:"password_expired"` // % users with expired passwords
	LockedOut       int `json:"locked_out"`       // % users currently locked out
	Inactive        int `json:"inactive"`         // % users inactive for 90+ days
}

// AppMetrics contains application lifecycle percentages (all 0-100).
type AppMetrics struct {
	ProvisioningEnabled   int `json:"provisioning_enabled"`   // % apps with auto-provisioning
	DeprovisioningEnabled int `json:"deprovisioning_enabled"` // % apps with auto-deprovisioning
}

// PolicyConfig contains aggregated policy settings across all active policies.
type PolicyConfig struct {
	PolicyCount               int  `json:"policy_count"`                 // Number of active sign-on policies
	MFARequiredAll            bool `json:"mfa_required_all"`             // All policies require MFA
	MFARequiredAny            bool `json:"mfa_required_any"`             // At least one policy requires MFA
	SessionLifetimeMinMinutes *int `json:"session_lifetime_min_minutes"` // Shortest session lifetime across policies
	SessionLifetimeMaxMinutes *int `json:"session_lifetime_max_minutes"` // Longest session lifetime across policies
	IdleTimeoutMinMinutes     *int `json:"idle_timeout_min_minutes"`     // Shortest idle timeout across policies
	IdleTimeoutMaxMinutes     *int `json:"idle_timeout_max_minutes"`     // Longest idle timeout across policies
}

// NewOrgPosture creates a new OrgPosture with the current timestamp.
func NewOrgPosture(orgDomain string) *OrgPosture {
	return &OrgPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		OrgDomain:     orgDomain,
	}
}

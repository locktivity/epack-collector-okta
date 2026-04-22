// Package collector provides Okta organization posture collection functionality.
package collector

import "time"

// SchemaVersion is the version of the output schema.
const SchemaVersion = "1.0.0"

// InactiveDaysThreshold is the number of days after which a user is considered inactive.
const InactiveDaysThreshold = 90

// StatusFunc is called to report indeterminate status updates.
type StatusFunc func(message string)

// ProgressFunc is called to report determinate progress (current/total).
type ProgressFunc func(current, total int64, message string)

// Config holds the collector configuration passed via stdin.
type Config struct {
	OrgDomain  string `json:"org_domain"`  // e.g., "company.okta.com"
	ClientID   string `json:"client_id"`   // OAuth 2.0 client ID
	KeyID      string `json:"key_id"`      // Key ID (kid) for JWT header - from Okta public key
	PrivateKey string `json:"private_key"` // Private key for JWT assertion (PEM)
	APIToken   string `json:"api_token"`   // SSWS token (legacy, less secure)

	// Progress callbacks (optional, set by main to report status)
	OnStatus   StatusFunc   `json:"-"`
	OnProgress ProgressFunc `json:"-"`
}

// OrgPosture represents the collected security posture of an Okta organization.
type OrgPosture struct {
	SchemaVersion    string                  `json:"schema_version"`
	CollectedAt      string                  `json:"collected_at"`
	OrgDomain        string                  `json:"org_domain"`
	Posture          Posture                 `json:"posture"`
	Users            UserMetrics             `json:"users"`
	Apps             AppMetrics              `json:"apps"`
	PrivilegedAccess PrivilegedAccessMetrics `json:"privileged_access"`
	Policy           PolicyConfig            `json:"policy"`
	DeviceAccess     DeviceAccessMetrics     `json:"device_access"`
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
	Suspended       int `json:"suspended"`        // % users currently suspended
}

// AppMetrics contains application lifecycle percentages (all 0-100).
type AppMetrics struct {
	ProvisioningEnabled   int `json:"provisioning_enabled"`   // % apps with auto-provisioning
	DeprovisioningEnabled int `json:"deprovisioning_enabled"` // % apps with auto-deprovisioning
}

// PrivilegedAccessMetrics contains privileged account counts and MFA coverage.
type PrivilegedAccessMetrics struct {
	PrivilegedUsersCount           int `json:"privileged_users_count"`
	SuperAdminCount                int `json:"super_admin_count"`
	StandingPrivilegedUsersCount   int `json:"standing_privileged_users_count"`
	PrivilegedMFACoveragePct       int `json:"privileged_mfa_coverage_pct"`
	PrivilegedPhishingResistantPct int `json:"privileged_phishing_resistant_pct"`
}

// PolicyConfig contains aggregated policy settings across all active policies.
type PolicyConfig struct {
	PolicyCount               int  `json:"policy_count"`                 // Number of active sign-on policies
	MFARequiredAll            bool `json:"mfa_required_all"`             // MFA is required for all non-deprovisioned users
	MFARequiredAny            bool `json:"mfa_required_any"`             // MFA is required for at least one non-deprovisioned user
	MFARequiredCoveragePct    int  `json:"mfa_required_coverage_pct"`    // % of non-deprovisioned users covered by an MFA requirement
	SessionLifetimeMinMinutes *int `json:"session_lifetime_min_minutes"` // Shortest session lifetime across active sign-on rules
	SessionLifetimeMaxMinutes *int `json:"session_lifetime_max_minutes"` // Longest session lifetime across active sign-on rules
	IdleTimeoutMinMinutes     *int `json:"idle_timeout_min_minutes"`     // Shortest idle timeout across active sign-on rules
	IdleTimeoutMaxMinutes     *int `json:"idle_timeout_max_minutes"`     // Longest idle timeout across active sign-on rules
}

// DeviceAccessMetrics contains device access enforcement posture.
type DeviceAccessMetrics struct {
	ManagedDeviceRequired            bool `json:"managed_device_required"`              // Whether any sign-on policy rule requires managed devices
	ManagedDeviceRequiredCoveragePct int  `json:"managed_device_required_coverage_pct"` // % of users covered by a managed device requirement
	ManagedDeviceRequiredForAdmins   bool `json:"managed_device_required_for_admins"`   // Whether all privileged users are covered by a managed device requirement
	DeviceAssurancePoliciesCount     int  `json:"device_assurance_policies_count"`      // Number of device assurance policies defined
}

// NewOrgPosture creates a new OrgPosture with the current timestamp.
func NewOrgPosture(orgDomain string) *OrgPosture {
	return &OrgPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		OrgDomain:     orgDomain,
	}
}

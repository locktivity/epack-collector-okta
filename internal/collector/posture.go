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
	CollectedAtLevel string                  `json:"collected_at_level"`
	OrgDomain        string                  `json:"org_domain"`
	Posture          Posture                 `json:"posture"`
	Users            UserMetrics             `json:"users"`
	Apps             AppMetrics              `json:"apps"`
	PrivilegedAccess PrivilegedAccessMetrics `json:"privileged_access"`
	Policy           PolicyConfig            `json:"policy"`
	DeviceAccess     DeviceAccessMetrics     `json:"device_access"`

	// Each is a pointer so a surface that could not be collected is omitted
	// rather than emitted empty.
	Groups            *Groups            `json:"groups,omitempty"`
	NetworkZones      *NetworkZones      `json:"network_zones,omitempty"`
	IdentityProviders *IdentityProviders `json:"identity_providers,omitempty"`
	APITokens         *APITokens         `json:"api_tokens,omitempty"`
	Hooks             *Hooks             `json:"hooks,omitempty"`
	SystemLog         *SystemLog         `json:"system_log,omitempty"`
	OrgSettings       *OrgSettings       `json:"org_settings,omitempty"`

	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`
}

// Diagnostics contains warnings encountered during collection. It distinguishes
// permission / feature-license gaps (which skip a surface) from genuine
// disablement, so a customer can see which scopes to grant.
type Diagnostics struct {
	Warnings []string `json:"warnings,omitempty"`
}

// Posture contains high-level security posture scores (all percentages 0-100).
//
// Audit adds per-factor-type enrollment counts and the MFA-disabled-user count.
type Posture struct {
	MFACoverage          int `json:"mfa_coverage"`           // % users with any MFA enrolled
	MFAPhishingResistant int `json:"mfa_phishing_resistant"` // % users with phishing-resistant MFA (WebAuthn/FIDO2, U2F, or Okta FastPass)
	SSOCoverage          int `json:"sso_coverage"`           // % apps using SSO (SAML/OIDC/WS-Fed)

	// Audit-level fields.
	PerFactorType         []FactorTypeCount `json:"per_factor_type,omitempty"`          // Enrolled-user count per active factor type
	MFADisabledUsersCount *int              `json:"mfa_disabled_users_count,omitempty"` // Non-deprovisioned users with no active MFA
}

// FactorTypeCount records how many users have at least one active factor of a
// given type (audit+).
type FactorTypeCount struct {
	FactorType    string `json:"factor_type"`    // e.g. push, webauthn, sms, token:software:totp
	EnrolledUsers int    `json:"enrolled_users"` // Users with >= 1 active factor of this type
}

// NewOrgPosture creates a new OrgPosture with the current timestamp.
func NewOrgPosture(orgDomain string) *OrgPosture {
	return &OrgPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		OrgDomain:     orgDomain,
	}
}

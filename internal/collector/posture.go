// Package collector provides Okta organization posture collection functionality.
package collector

import (
	"net/http"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

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

	// HTTPClient makes every Okta call. Run builds it with
	// componentsdk.NewHTTPClient.
	HTTPClient *http.Client `json:"-"`
	// Recorder takes a gap for each value the collector leaves out.
	Recorder *componentsdk.Recorder `json:"-"`
	// Now is the run's clock. It defaults to the wall clock.
	Now func() time.Time `json:"-"`
}

// Validate checks the configuration before any call is made.
func (c Config) Validate() error {
	if c.OrgDomain == "" {
		return componentsdk.NewConfigError("org_domain is required")
	}
	if okta.Host(c.OrgDomain) == "" {
		return componentsdk.NewConfigError("org_domain %q does not name a host", c.OrgDomain)
	}
	switch {
	case c.usesOAuth():
		if c.KeyID == "" {
			return componentsdk.NewConfigError("key_id is required for OAuth 2.0 authentication")
		}
	case c.APIToken != "":
	default:
		return componentsdk.NewConfigError("authentication required: provide client_id + key_id + OKTA_PRIVATE_KEY or OKTA_API_TOKEN")
	}
	return nil
}

// usesOAuth reports whether the service-app credentials are set, which take
// precedence over an API token.
func (c Config) usesOAuth() bool {
	return c.ClientID != "" && c.PrivateKey != ""
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
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
// A score is null when it could not be read, or when there are no users or
// apps to measure.
//
// Audit adds per-factor-type enrollment counts and the MFA-disabled-user count.
type Posture struct {
	MFACoverage          *int `json:"mfa_coverage"`           // % users with any MFA enrolled
	MFAPhishingResistant *int `json:"mfa_phishing_resistant"` // % users with phishing-resistant MFA (WebAuthn/FIDO2, U2F, or Okta FastPass)
	SSOCoverage          *int `json:"sso_coverage"`           // % apps using SSO (SAML/OIDC/WS-Fed)

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

// NewOrgPosture creates a new OrgPosture collected at now.
func NewOrgPosture(orgDomain string, now time.Time) *OrgPosture {
	return &OrgPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   now.UTC().Format(time.RFC3339),
		OrgDomain:     orgDomain,
	}
}

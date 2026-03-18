// Package collector provides Okta organization posture collection functionality.
package collector

import "time"

// IDPPosture represents the normalized identity provider posture.
// This follows the evidencepack/idp-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for Okta, Ping, Entra, etc.).
type IDPPosture struct {
	SchemaVersion string               `json:"schema_version"`
	CollectedAt   string               `json:"collected_at"`
	Provider      string               `json:"provider"`
	OrgDomain     string               `json:"org_domain"`
	UserSecurity  IDPPostureUserSecurity `json:"user_security"`
	AppSecurity   IDPPostureAppSecurity  `json:"app_security"`
	Policy        IDPPosturePolicy       `json:"policy"`
}

// IDPPostureUserSecurity contains user security metrics.
type IDPPostureUserSecurity struct {
	MFACoveragePct            float64 `json:"mfa_coverage_pct"`
	MFAPhishingResistantPct   float64 `json:"mfa_phishing_resistant_pct"`
	InactivePct               float64 `json:"inactive_pct"`
	LockedOutPct              float64 `json:"locked_out_pct"`
}

// IDPPostureAppSecurity contains application security metrics.
type IDPPostureAppSecurity struct {
	SSOCoveragePct           float64 `json:"sso_coverage_pct"`
	ProvisioningEnabledPct   float64 `json:"provisioning_enabled_pct"`
}

// IDPPosturePolicy contains aggregated policy settings.
type IDPPosturePolicy struct {
	MFARequired           bool `json:"mfa_required"`
	SessionLifetimeMaxMin int  `json:"session_lifetime_max_min"`
	IdleTimeoutMaxMin     int  `json:"idle_timeout_max_min"`
}

// ToIDPPosture transforms detailed Okta output to normalized idp-posture format.
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	posture := &IDPPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		Provider:      "okta",
		OrgDomain:     o.OrgDomain,
		UserSecurity: IDPPostureUserSecurity{
			MFACoveragePct:          float64(o.Posture.MFACoverage),
			MFAPhishingResistantPct: float64(o.Posture.MFAPhishingResistant),
			InactivePct:             float64(o.Users.Inactive),
			LockedOutPct:            float64(o.Users.LockedOut),
		},
		AppSecurity: IDPPostureAppSecurity{
			SSOCoveragePct:         float64(o.Posture.SSOCoverage),
			ProvisioningEnabledPct: float64(o.Apps.ProvisioningEnabled),
		},
		Policy: IDPPosturePolicy{
			MFARequired: o.Policy.MFARequiredAll || o.Policy.MFARequiredAny,
		},
	}

	// Use max values for session/idle timeouts (most permissive across policies)
	if o.Policy.SessionLifetimeMaxMinutes != nil {
		posture.Policy.SessionLifetimeMaxMin = *o.Policy.SessionLifetimeMaxMinutes
	}
	if o.Policy.IdleTimeoutMaxMinutes != nil {
		posture.Policy.IdleTimeoutMaxMin = *o.Policy.IdleTimeoutMaxMinutes
	}

	return posture
}

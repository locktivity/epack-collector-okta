// Package collector provides Okta organization posture collection functionality.
package collector

import "time"

// IDPPosture represents the normalized identity provider posture.
// This follows the evidencepack/idp-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for Okta, Ping, Entra, etc.).
type IDPPosture struct {
	SchemaVersion    string                      `json:"schema_version"`
	CollectedAt      string                      `json:"collected_at"`
	Provider         string                      `json:"provider"`
	OrgDomain        string                      `json:"org_domain"`
	UserSecurity     IDPPostureUserSecurity      `json:"user_security"`
	AppSecurity      *IDPPostureAppSecurity      `json:"app_security,omitempty"`
	PrivilegedAccess *IDPPosturePrivilegedAccess `json:"privileged_access,omitempty"`
	Policy           *IDPPosturePolicy           `json:"policy,omitempty"`
	Lifecycle        *IDPPostureLifecycle        `json:"lifecycle,omitempty"`
	DeviceAccess     *IDPPostureDeviceAccess     `json:"device_access,omitempty"`
}

// IDPPostureUserSecurity contains user security metrics.
type IDPPostureUserSecurity struct {
	MFACoveragePct                float64  `json:"mfa_coverage_pct"`
	MFAPhishingResistantPct       float64  `json:"mfa_phishing_resistant_pct"`
	InactivePct                   float64  `json:"inactive_pct"`
	LockedOutPct                  float64  `json:"locked_out_pct"`
	WeakPasswordPct               *float64 `json:"weak_password_pct,omitempty"`
	PasswordPolicyNoncompliantPct *float64 `json:"password_policy_noncompliant_pct,omitempty"`
}

// IDPPostureAppSecurity contains application security metrics.
type IDPPostureAppSecurity struct {
	SSOCoveragePct                float64 `json:"sso_coverage_pct"`
	ProvisioningEnabledPct        float64 `json:"provisioning_enabled_pct"`
	DeprovisioningEnabledPct      float64 `json:"deprovisioning_enabled_pct"`
	AuthorizedThirdPartyAppsCount *int    `json:"authorized_third_party_apps_count,omitempty"`
}

// IDPPosturePrivilegedAccess contains privileged account posture metrics.
type IDPPosturePrivilegedAccess struct {
	PrivilegedUsersCount           int      `json:"privileged_users_count"`
	SuperAdminCount                int      `json:"super_admin_count"`
	PrivilegedMFACoveragePct       *float64 `json:"privileged_mfa_coverage_pct,omitempty"`
	PrivilegedPhishingResistantPct *float64 `json:"privileged_phishing_resistant_pct,omitempty"`
	StandingPrivilegedUsersCount   *int     `json:"standing_privileged_users_count,omitempty"`
}

// IDPPosturePolicy contains aggregated policy settings.
type IDPPosturePolicy struct {
	MFARequired                            bool     `json:"mfa_required"`
	MFARequiredCoveragePct                 *float64 `json:"mfa_required_coverage_pct,omitempty"`
	SessionLifetimeMaxMin                  *int     `json:"session_lifetime_max_min,omitempty"`
	IdleTimeoutMaxMin                      *int     `json:"idle_timeout_max_min,omitempty"`
	LegacyAuthBlocked                      *bool    `json:"legacy_auth_blocked,omitempty"`
	PhishingResistantRequiredForPrivileged *bool    `json:"phishing_resistant_required_for_privileged,omitempty"`
}

// IDPPostureLifecycle contains account lifecycle posture metrics.
type IDPPostureLifecycle struct {
	SuspendedPct *float64 `json:"suspended_pct,omitempty"`
	ArchivedPct  *float64 `json:"archived_pct,omitempty"`
}

// IDPPostureDeviceAccess contains managed-device enforcement posture.
type IDPPostureDeviceAccess struct {
	ManagedDeviceRequired          *bool `json:"managed_device_required,omitempty"`
	ManagedDeviceRequiredForAdmins *bool `json:"managed_device_required_for_admins,omitempty"`
}

// ToIDPPosture transforms detailed Okta output to normalized idp-posture format.
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	suspendedPct := float64(o.Users.Suspended)
	privilegedMFACoveragePct := float64(o.PrivilegedAccess.PrivilegedMFACoveragePct)
	privilegedPhishingResistantPct := float64(o.PrivilegedAccess.PrivilegedPhishingResistantPct)
	standingPrivilegedUsersCount := o.PrivilegedAccess.StandingPrivilegedUsersCount
	mfaRequiredCoveragePct := float64(o.Policy.MFARequiredCoveragePct)

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
		AppSecurity: &IDPPostureAppSecurity{
			SSOCoveragePct:           float64(o.Posture.SSOCoverage),
			ProvisioningEnabledPct:   float64(o.Apps.ProvisioningEnabled),
			DeprovisioningEnabledPct: float64(o.Apps.DeprovisioningEnabled),
		},
		PrivilegedAccess: &IDPPosturePrivilegedAccess{
			PrivilegedUsersCount:           o.PrivilegedAccess.PrivilegedUsersCount,
			SuperAdminCount:                o.PrivilegedAccess.SuperAdminCount,
			PrivilegedMFACoveragePct:       &privilegedMFACoveragePct,
			PrivilegedPhishingResistantPct: &privilegedPhishingResistantPct,
			StandingPrivilegedUsersCount:   &standingPrivilegedUsersCount,
		},
		Policy: &IDPPosturePolicy{},
		Lifecycle: &IDPPostureLifecycle{
			SuspendedPct: &suspendedPct,
		},
	}

	posture.Policy.MFARequired = o.Policy.MFARequiredCoveragePct == 100
	posture.Policy.MFARequiredCoveragePct = &mfaRequiredCoveragePct

	// Use max values for session/idle timeouts (most permissive across policies)
	if o.Policy.SessionLifetimeMaxMinutes != nil {
		posture.Policy.SessionLifetimeMaxMin = o.Policy.SessionLifetimeMaxMinutes
	}
	if o.Policy.IdleTimeoutMaxMinutes != nil {
		posture.Policy.IdleTimeoutMaxMin = o.Policy.IdleTimeoutMaxMinutes
	}

	// Device access - only emit if we have positive evidence
	if o.DeviceAccess.ManagedDeviceRequired {
		managedDeviceRequired := true
		posture.DeviceAccess = &IDPPostureDeviceAccess{
			ManagedDeviceRequired: &managedDeviceRequired,
		}
		if o.DeviceAccess.ManagedDeviceRequiredForAdmins {
			managedDeviceRequiredForAdmins := true
			posture.DeviceAccess.ManagedDeviceRequiredForAdmins = &managedDeviceRequiredForAdmins
		}
	}

	return posture
}

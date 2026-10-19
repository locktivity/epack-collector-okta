// Package collector provides Okta organization posture collection functionality.
package collector

// IDPPosture represents the normalized identity provider posture.
// This follows the evidencepack/idp-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for Okta, Ping, Entra, etc.).
// A value the detailed artifact left out is absent here too, with the same
// gap.
type IDPPosture struct {
	SchemaVersion    string                      `json:"schema_version"`
	CollectedAt      string                      `json:"collected_at"`
	Provider         string                      `json:"provider"`
	OrgDomain        string                      `json:"org_domain"`
	UserSecurity     *IDPPostureUserSecurity     `json:"user_security,omitempty"`
	AppSecurity      *IDPPostureAppSecurity      `json:"app_security,omitempty"`
	PrivilegedAccess *IDPPosturePrivilegedAccess `json:"privileged_access,omitempty"`
	Policy           *IDPPosturePolicy           `json:"policy,omitempty"`
	Lifecycle        *IDPPostureLifecycle        `json:"lifecycle,omitempty"`
	DeviceAccess     *IDPPostureDeviceAccess     `json:"device_access,omitempty"`
}

// IDPPostureUserSecurity contains user security metrics.
type IDPPostureUserSecurity struct {
	MFACoveragePct                *float64 `json:"mfa_coverage_pct,omitempty"`
	MFAPhishingResistantPct       *float64 `json:"mfa_phishing_resistant_pct,omitempty"`
	InactivePct                   *float64 `json:"inactive_pct,omitempty"`
	LockedOutPct                  *float64 `json:"locked_out_pct,omitempty"`
	WeakPasswordPct               *float64 `json:"weak_password_pct,omitempty"`
	PasswordPolicyNoncompliantPct *float64 `json:"password_policy_noncompliant_pct,omitempty"`
}

// IDPPostureAppSecurity contains application security metrics.
type IDPPostureAppSecurity struct {
	SSOCoveragePct                *float64 `json:"sso_coverage_pct,omitempty"`
	ProvisioningEnabledPct        *float64 `json:"provisioning_enabled_pct,omitempty"`
	DeprovisioningEnabledPct      *float64 `json:"deprovisioning_enabled_pct,omitempty"`
	AuthorizedThirdPartyAppsCount *int     `json:"authorized_third_party_apps_count,omitempty"`
}

// IDPPosturePrivilegedAccess contains privileged account posture metrics.
type IDPPosturePrivilegedAccess struct {
	PrivilegedUsersCount           *int     `json:"privileged_users_count,omitempty"`
	SuperAdminCount                *int     `json:"super_admin_count,omitempty"`
	PrivilegedMFACoveragePct       *float64 `json:"privileged_mfa_coverage_pct,omitempty"`
	PrivilegedPhishingResistantPct *float64 `json:"privileged_phishing_resistant_pct,omitempty"`
	StandingPrivilegedUsersCount   *int     `json:"standing_privileged_users_count,omitempty"`
}

// IDPPosturePolicy contains aggregated policy settings.
type IDPPosturePolicy struct {
	MFARequired                            *bool    `json:"mfa_required,omitempty"`
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

// ToIDPPosture transforms detailed Okta output to normalized idp-posture
// format. It returns nil when the detailed artifact holds none of the values
// the normalized one copies.
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	posture := &IDPPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   o.CollectedAt,
		Provider:      "okta",
		OrgDomain:     o.OrgDomain,
	}

	userSecurity := IDPPostureUserSecurity{
		MFACoveragePct:          floatPtr(o.Posture.MFACoverage),
		MFAPhishingResistantPct: floatPtr(o.Posture.MFAPhishingResistant),
		InactivePct:             floatPtr(o.Users.Inactive),
		LockedOutPct:            floatPtr(o.Users.LockedOut),
	}
	if userSecurity != (IDPPostureUserSecurity{}) {
		posture.UserSecurity = &userSecurity
	}

	appSecurity := IDPPostureAppSecurity{
		SSOCoveragePct:           floatPtr(o.Posture.SSOCoverage),
		ProvisioningEnabledPct:   floatPtr(o.Apps.ProvisioningEnabled),
		DeprovisioningEnabledPct: floatPtr(o.Apps.DeprovisioningEnabled),
	}
	if appSecurity != (IDPPostureAppSecurity{}) {
		posture.AppSecurity = &appSecurity
	}

	privileged := IDPPosturePrivilegedAccess{
		PrivilegedUsersCount:           o.PrivilegedAccess.PrivilegedUsersCount,
		SuperAdminCount:                o.PrivilegedAccess.SuperAdminCount,
		PrivilegedMFACoveragePct:       floatPtr(o.PrivilegedAccess.PrivilegedMFACoveragePct),
		PrivilegedPhishingResistantPct: floatPtr(o.PrivilegedAccess.PrivilegedPhishingResistantPct),
		StandingPrivilegedUsersCount:   o.PrivilegedAccess.StandingPrivilegedUsersCount,
	}
	if privileged != (IDPPosturePrivilegedAccess{}) {
		posture.PrivilegedAccess = &privileged
	}

	// mfa_required means every user is covered, which mfa_required_all
	// already says.
	policy := IDPPosturePolicy{
		MFARequired:            o.Policy.MFARequiredAll,
		MFARequiredCoveragePct: floatPtr(o.Policy.MFARequiredCoveragePct),
		SessionLifetimeMaxMin:  o.Policy.SessionLifetimeMaxMinutes,
		IdleTimeoutMaxMin:      o.Policy.IdleTimeoutMaxMinutes,
	}
	if policy != (IDPPosturePolicy{}) {
		posture.Policy = &policy
	}

	if o.Users.Suspended != nil {
		posture.Lifecycle = &IDPPostureLifecycle{SuspendedPct: floatPtr(o.Users.Suspended)}
	}

	// Device access - only emit if we have positive evidence
	if isTrue(o.DeviceAccess.ManagedDeviceRequired) {
		posture.DeviceAccess = &IDPPostureDeviceAccess{ManagedDeviceRequired: boolPtr(true)}
		if isTrue(o.DeviceAccess.ManagedDeviceRequiredForAdmins) {
			posture.DeviceAccess.ManagedDeviceRequiredForAdmins = boolPtr(true)
		}
	}

	if posture.UserSecurity == nil && posture.AppSecurity == nil && posture.PrivilegedAccess == nil &&
		posture.Policy == nil && posture.Lifecycle == nil && posture.DeviceAccess == nil {
		return nil
	}
	return posture
}

// idpPostureSources maps each normalized value to the detailed value it
// copies, so a gap on the detailed value carries over.
var idpPostureSources = []struct{ normalized, detailed string }{
	{"/user_security/mfa_coverage_pct", "/posture/mfa_coverage"},
	{"/user_security/mfa_phishing_resistant_pct", "/posture/mfa_phishing_resistant"},
	{"/user_security/inactive_pct", "/users/inactive"},
	{"/user_security/locked_out_pct", "/users/locked_out"},
	{"/app_security/sso_coverage_pct", "/posture/sso_coverage"},
	{"/app_security/provisioning_enabled_pct", "/apps/provisioning_enabled"},
	{"/app_security/deprovisioning_enabled_pct", "/apps/deprovisioning_enabled"},
	{"/privileged_access/privileged_users_count", "/privileged_access/privileged_users_count"},
	{"/privileged_access/super_admin_count", "/privileged_access/super_admin_count"},
	{"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_mfa_coverage_pct"},
	{"/privileged_access/privileged_phishing_resistant_pct", "/privileged_access/privileged_phishing_resistant_pct"},
	{"/privileged_access/standing_privileged_users_count", "/privileged_access/standing_privileged_users_count"},
	{"/policy/mfa_required", "/policy/mfa_required_all"},
	{"/policy/mfa_required_coverage_pct", "/policy/mfa_required_coverage_pct"},
	{"/policy/session_lifetime_max_min", "/policy/session_lifetime_max_minutes"},
	{"/policy/idle_timeout_max_min", "/policy/idle_timeout_max_minutes"},
	{"/lifecycle/suspended_pct", "/users/suspended"},
	{"/device_access/managed_device_required", "/device_access/managed_device_required"},
	{"/device_access/managed_device_required_for_admins", "/device_access/managed_device_required_for_admins"},
}

func (c *Collector) mirrorIDPPostureGaps() {
	for _, source := range idpPostureSources {
		c.gaps.mirror(source.detailed, source.normalized)
	}
}

func floatPtr(v *int) *float64 {
	if v == nil {
		return nil
	}
	f := float64(*v)
	return &f
}

func isTrue(b *bool) bool {
	return b != nil && *b
}

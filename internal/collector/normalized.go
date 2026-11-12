// Package collector provides Okta organization posture collection functionality.
package collector

import (
	"encoding/json"

	"github.com/locktivity/epack/componentsdk"
)

// IDPPosture represents the normalized identity provider posture.
// This follows the evidencepack/idp-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for Okta, Ping, Entra, etc.).
// A value the detailed artifact left out is absent here too, with the same
// gap. A percentage over an empty population is null. The counts behind the
// percentages are written from the audit level, as the schema marks them,
// and the present flags at every level.
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

// Percentage is a normalized percentage. It is left out when Read is false.
// Otherwise it is written as Value, which is nil over an empty population.
type Percentage struct {
	Value *float64
	Read  bool
}

// IsZero reports whether the percentage was not read, for omitzero.
func (p Percentage) IsZero() bool { return !p.Read }

// MarshalJSON writes the value, or null.
func (p Percentage) MarshalJSON() ([]byte, error) { return json.Marshal(p.Value) }

// IDPPostureUserSecurity contains user security metrics. Okta has no data on
// weak passwords or password policy compliance, so those values are left
// out with an unsupported gap. See idpPostureLeftOut.
type IDPPostureUserSecurity struct {
	UsersPresent               *bool      `json:"users_present,omitempty"`
	UserCount                  *int       `json:"user_count,omitempty"`
	MFAUserCount               *int       `json:"mfa_user_count,omitempty"`
	PhishingResistantUserCount *int       `json:"phishing_resistant_user_count,omitempty"`
	InactiveUserCount          *int       `json:"inactive_user_count,omitempty"`
	LockedOutUserCount         *int       `json:"locked_out_user_count,omitempty"`
	MFACoveragePct             Percentage `json:"mfa_coverage_pct,omitzero"`
	MFAPhishingResistantPct    Percentage `json:"mfa_phishing_resistant_pct,omitzero"`
	InactivePct                Percentage `json:"inactive_pct,omitzero"`
	LockedOutPct               Percentage `json:"locked_out_pct,omitzero"`
}

// IDPPostureAppSecurity contains application security metrics.
type IDPPostureAppSecurity struct {
	AppsPresent                   *bool      `json:"apps_present,omitempty"`
	AppCount                      *int       `json:"app_count,omitempty"`
	SSOAppCount                   *int       `json:"sso_app_count,omitempty"`
	ProvisioningAppCount          *int       `json:"provisioning_app_count,omitempty"`
	DeprovisioningAppCount        *int       `json:"deprovisioning_app_count,omitempty"`
	SSOCoveragePct                Percentage `json:"sso_coverage_pct,omitzero"`
	ProvisioningEnabledPct        Percentage `json:"provisioning_enabled_pct,omitzero"`
	DeprovisioningEnabledPct      Percentage `json:"deprovisioning_enabled_pct,omitzero"`
	AuthorizedThirdPartyAppsCount *int       `json:"authorized_third_party_apps_count,omitempty"`
}

// IDPPosturePrivilegedAccess contains privileged account posture metrics.
type IDPPosturePrivilegedAccess struct {
	PrivilegedUsersPresent               *bool      `json:"privileged_users_present,omitempty"`
	PrivilegedUsersCount                 *int       `json:"privileged_users_count,omitempty"`
	SuperAdminCount                      *int       `json:"super_admin_count,omitempty"`
	PrivilegedMFAUserCount               *int       `json:"privileged_mfa_user_count,omitempty"`
	PrivilegedPhishingResistantUserCount *int       `json:"privileged_phishing_resistant_user_count,omitempty"`
	PrivilegedMFACoveragePct             Percentage `json:"privileged_mfa_coverage_pct,omitzero"`
	PrivilegedPhishingResistantPct       Percentage `json:"privileged_phishing_resistant_pct,omitzero"`
	StandingPrivilegedUsersPresent       *bool      `json:"standing_privileged_users_present,omitempty"`
	StandingPrivilegedUsersCount         *int       `json:"standing_privileged_users_count,omitempty"`
}

// IDPPosturePolicy contains aggregated policy settings.
type IDPPosturePolicy struct {
	MFARequired                            *bool      `json:"mfa_required,omitempty"`
	MFARequiredUserCount                   *int       `json:"mfa_required_user_count,omitempty"`
	MFARequiredCoveragePct                 Percentage `json:"mfa_required_coverage_pct,omitzero"`
	SessionLifetimeMaxMin                  *int       `json:"session_lifetime_max_min,omitempty"`
	IdleTimeoutMaxMin                      *int       `json:"idle_timeout_max_min,omitempty"`
	LegacyAuthBlocked                      *bool      `json:"legacy_auth_blocked,omitempty"`
	PhishingResistantRequiredForPrivileged *bool      `json:"phishing_resistant_required_for_privileged,omitempty"`
}

// IDPPostureLifecycle contains account lifecycle posture metrics. Its
// accounts are the users other than deprovisioned ones, in every other
// state. Okta has no archived account state, so the archived values are
// left out with an unsupported gap.
type IDPPostureLifecycle struct {
	AccountsPresent       *bool      `json:"accounts_present,omitempty"`
	AccountCount          *int       `json:"account_count,omitempty"`
	SuspendedAccountCount *int       `json:"suspended_account_count,omitempty"`
	SuspendedPct          Percentage `json:"suspended_pct,omitzero"`
}

// IDPPostureDeviceAccess contains managed-device enforcement posture.
type IDPPostureDeviceAccess struct {
	ManagedDeviceRequired          *bool `json:"managed_device_required,omitempty"`
	ManagedDeviceRequiredForAdmins *bool `json:"managed_device_required_for_admins,omitempty"`
}

// ToIDPPosture transforms detailed Okta output to normalized idp-posture
// format. It returns nil when the detailed artifact holds none of the values
// the normalized one copies. Each percentage is taken from its counts and
// rounded as the idp-posture schema says. Where more is worse, as with
// inactive accounts, it rounds up.
func (o *OrgPosture) ToIDPPosture() *IDPPosture {
	posture := &IDPPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   o.CollectedAt,
		Provider:      "okta",
		OrgDomain:     o.OrgDomain,
	}
	audit := componentsdk.Level(o.CollectedAtLevel).AtLeast(componentsdk.LevelAudit)
	atAudit := func(count *int) *int {
		if audit {
			return count
		}
		return nil
	}
	users, accounts, apps := o.Users.EnabledCount, o.Users.TotalCount, o.Apps.TotalCount

	userSecurity := IDPPostureUserSecurity{
		UsersPresent:               present(users),
		UserCount:                  atAudit(users),
		MFAUserCount:               atAudit(o.Posture.MFAEnrolledUsersCount),
		PhishingResistantUserCount: atAudit(o.Posture.MFAPhishingResistantUsersCount),
		InactiveUserCount:          atAudit(o.Users.InactiveCount),
		LockedOutUserCount:         atAudit(o.Users.LockedOutCount),
		MFACoveragePct:             share(o.Posture.MFAEnrolledUsersCount, users, componentsdk.RoundDown),
		MFAPhishingResistantPct:    share(o.Posture.MFAPhishingResistantUsersCount, users, componentsdk.RoundDown),
		InactivePct:                share(o.Users.InactiveCount, users, componentsdk.RoundUp),
		LockedOutPct:               share(o.Users.LockedOutCount, users, componentsdk.RoundUp),
	}
	usersElsewhere := len(o.elsewhere.users) > 0 || o.elsewhere.err != nil
	if usersElsewhere {
		userSecurity.MFAUserCount, userSecurity.PhishingResistantUserCount = nil, nil
		userSecurity.MFACoveragePct, userSecurity.MFAPhishingResistantPct = Percentage{}, Percentage{}
	}
	if userSecurity != (IDPPostureUserSecurity{}) {
		posture.UserSecurity = &userSecurity
	}

	appSecurity := IDPPostureAppSecurity{
		AppsPresent:              present(apps),
		AppCount:                 atAudit(apps),
		SSOAppCount:              atAudit(o.Apps.SSOCount),
		ProvisioningAppCount:     atAudit(o.Apps.ProvisioningEnabledCount),
		DeprovisioningAppCount:   atAudit(o.Apps.DeprovisioningEnabledCount),
		SSOCoveragePct:           share(o.Apps.SSOCount, apps, componentsdk.RoundDown),
		ProvisioningEnabledPct:   share(o.Apps.ProvisioningEnabledCount, apps, componentsdk.RoundDown),
		DeprovisioningEnabledPct: share(o.Apps.DeprovisioningEnabledCount, apps, componentsdk.RoundDown),
	}
	if appSecurity != (IDPPostureAppSecurity{}) {
		posture.AppSecurity = &appSecurity
	}

	pa := o.PrivilegedAccess
	privileged := IDPPosturePrivilegedAccess{
		PrivilegedUsersPresent:               present(pa.PrivilegedUsersCount),
		PrivilegedUsersCount:                 atAudit(pa.PrivilegedUsersCount),
		SuperAdminCount:                      atAudit(pa.SuperAdminCount),
		PrivilegedMFAUserCount:               atAudit(pa.PrivilegedMFAEnrolledCount),
		PrivilegedPhishingResistantUserCount: atAudit(pa.PrivilegedPhishingResistantCount),
		PrivilegedMFACoveragePct:             share(pa.PrivilegedMFAEnrolledCount, pa.PrivilegedUsersCount, componentsdk.RoundDown),
		PrivilegedPhishingResistantPct:       share(pa.PrivilegedPhishingResistantCount, pa.PrivilegedUsersCount, componentsdk.RoundDown),
		StandingPrivilegedUsersPresent:       present(pa.StandingPrivilegedUsersCount),
		StandingPrivilegedUsersCount:         atAudit(pa.StandingPrivilegedUsersCount),
	}
	if len(o.elsewhere.admins) > 0 || o.elsewhere.err != nil {
		privileged.PrivilegedMFAUserCount, privileged.PrivilegedPhishingResistantUserCount = nil, nil
		privileged.PrivilegedMFACoveragePct, privileged.PrivilegedPhishingResistantPct = Percentage{}, Percentage{}
	}
	if privileged != (IDPPosturePrivilegedAccess{}) {
		posture.PrivilegedAccess = &privileged
	}

	// mfa_required means every user is covered, setting aside the users
	// and groups policies exclude by name, as mfa_required_except_exclusions
	// says. The excluded users count as not covered. App sign-in policies
	// can require MFA of the people the sign-on policies leave out, and their
	// rules are not read. When an app has one, the MFA requirement values
	// they could change are left out.
	policy := IDPPosturePolicy{
		MFARequired:            o.Policy.MFARequiredExceptExclusions,
		MFARequiredUserCount:   atAudit(o.Policy.MFARequiredUsersCount),
		MFARequiredCoveragePct: share(o.Policy.MFARequiredUsersCount, users, componentsdk.RoundDown),
		SessionLifetimeMaxMin:  o.Policy.SessionLifetimeMaxMinutes,
		IdleTimeoutMaxMin:      o.Policy.IdleTimeoutMaxMinutes,
	}
	if o.Policy.mfaRequirementUnread() {
		policy.MFARequired = nil
	}
	if o.Policy.mfaCoverageUnread() || usersElsewhere {
		policy.MFARequiredUserCount = nil
		policy.MFARequiredCoveragePct = Percentage{}
	}
	if usersElsewhere {
		policy.MFARequired = nil
	}
	if policy != (IDPPosturePolicy{}) {
		posture.Policy = &policy
	}

	lifecycle := IDPPostureLifecycle{
		AccountsPresent:       present(accounts),
		AccountCount:          atAudit(accounts),
		SuspendedAccountCount: atAudit(o.Users.SuspendedCount),
		SuspendedPct:          share(o.Users.SuspendedCount, accounts, componentsdk.RoundUp),
	}
	if lifecycle != (IDPPostureLifecycle{}) {
		posture.Lifecycle = &lifecycle
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

// share returns count as a percentage of total, rounded as rounding says.
// It is null when total is 0, and left out when count or total was not read.
func share(count, total *int, rounding componentsdk.Rounding) Percentage {
	if total != nil && *total == 0 {
		return Percentage{Read: true}
	}
	if count == nil || total == nil {
		return Percentage{}
	}
	return Percentage{Value: floatPtr(componentsdk.Percent(*count, *total, rounding)), Read: true}
}

// idpPostureSources maps each normalized value to the detailed value it
// copies, so a gap on the detailed value carries over.
var idpPostureSources = []struct{ normalized, detailed string }{
	{"/user_security/users_present", "/users/enabled_count"},
	{"/user_security/user_count", "/users/enabled_count"},
	{"/user_security/mfa_user_count", "/posture/mfa_enrolled_users_count"},
	{"/user_security/phishing_resistant_user_count", "/posture/mfa_phishing_resistant_users_count"},
	{"/user_security/inactive_user_count", "/users/inactive_count"},
	{"/user_security/locked_out_user_count", "/users/locked_out_count"},
	{"/user_security/mfa_coverage_pct", "/posture/mfa_coverage"},
	{"/user_security/mfa_phishing_resistant_pct", "/posture/mfa_phishing_resistant"},
	{"/user_security/inactive_pct", "/users/inactive"},
	{"/user_security/locked_out_pct", "/users/locked_out"},
	{"/app_security/apps_present", "/apps/total_count"},
	{"/app_security/app_count", "/apps/total_count"},
	{"/app_security/sso_app_count", "/apps/sso_count"},
	{"/app_security/provisioning_app_count", "/apps/provisioning_enabled_count"},
	{"/app_security/deprovisioning_app_count", "/apps/deprovisioning_enabled_count"},
	{"/app_security/sso_coverage_pct", "/posture/sso_coverage"},
	{"/app_security/provisioning_enabled_pct", "/apps/provisioning_enabled"},
	{"/app_security/deprovisioning_enabled_pct", "/apps/deprovisioning_enabled"},
	{"/privileged_access/privileged_users_present", "/privileged_access/privileged_users_count"},
	{"/privileged_access/privileged_users_count", "/privileged_access/privileged_users_count"},
	{"/privileged_access/super_admin_count", "/privileged_access/super_admin_count"},
	{"/privileged_access/privileged_mfa_user_count", "/privileged_access/privileged_mfa_enrolled_count"},
	{"/privileged_access/privileged_phishing_resistant_user_count", "/privileged_access/privileged_phishing_resistant_count"},
	{"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_mfa_coverage_pct"},
	{"/privileged_access/privileged_phishing_resistant_pct", "/privileged_access/privileged_phishing_resistant_pct"},
	{"/privileged_access/standing_privileged_users_present", "/privileged_access/standing_privileged_users_count"},
	{"/privileged_access/standing_privileged_users_count", "/privileged_access/standing_privileged_users_count"},
	{"/policy/mfa_required", "/policy/mfa_required_except_exclusions"},
	{"/policy/mfa_required_user_count", "/policy/mfa_required_users_count"},
	{"/policy/mfa_required_coverage_pct", "/policy/mfa_required_coverage_pct"},
	{"/policy/session_lifetime_max_min", "/policy/session_lifetime_max_minutes"},
	{"/policy/idle_timeout_max_min", "/policy/idle_timeout_max_minutes"},
	{"/lifecycle/accounts_present", "/users/total_count"},
	{"/lifecycle/account_count", "/users/total_count"},
	{"/lifecycle/suspended_account_count", "/users/suspended_count"},
	{"/lifecycle/suspended_pct", "/users/suspended"},
	{"/device_access/managed_device_required", "/device_access/managed_device_required"},
	{"/device_access/managed_device_required_for_admins", "/device_access/managed_device_required_for_admins"},
}

func (c *Collector) mirrorIDPPostureGaps() {
	for _, source := range idpPostureSources {
		c.gaps.mirror(source.detailed, source.normalized)
	}
}

// idpPostureLeftOut lists the normalized values the collector leaves out,
// with the gap code and the reason, in pointer order, the order the result
// lists gaps in. Okta has no data for the unsupported ones. Okta reports the
// not_read ones through calls the collector does not make. The audit ones
// are audit-level counts.
var idpPostureLeftOut = []struct {
	pointer string
	code    componentsdk.Code
	reason  string
	audit   bool
}{
	{"/app_security/authorized_third_party_apps_count", componentsdk.CodeNotRead, userGrants, true},
	{"/lifecycle/archived_account_count", componentsdk.CodeUnsupported, archivedAccounts, true},
	{"/lifecycle/archived_pct", componentsdk.CodeUnsupported, archivedAccounts, false},
	{"/policy/legacy_auth_blocked", componentsdk.CodeNotRead, legacyAuth, false},
	{"/policy/phishing_resistant_required_for_privileged", componentsdk.CodeNotRead, accessPolicies, false},
	{"/user_security/password_policy_noncompliant_pct", componentsdk.CodeUnsupported, policyCompliance, false},
	{"/user_security/password_policy_noncompliant_user_count", componentsdk.CodeUnsupported, policyCompliance, true},
	{"/user_security/weak_password_pct", componentsdk.CodeUnsupported, weakPasswords, false},
	{"/user_security/weak_password_user_count", componentsdk.CodeUnsupported, weakPasswords, true},
}

const (
	weakPasswords    = "Okta does not report how strong each user's password is."
	policyCompliance = "Okta does not report whether each user's password meets the password policy."
	archivedAccounts = "Okta has no archived account state."
	userGrants       = "Okta's user grants API reports the apps each user has granted access to, which this collector does not read."
	accessPolicies   = "Okta's policies API reports each authentication policy's phishing-resistant requirement in its ACCESS_POLICY rules, which this collector does not read."
	appSignInMFA     = "Okta's policies API reports the MFA each app sign-in policy requires in its ACCESS_POLICY rules, which this collector does not read."
	legacyAuth       = "Okta sets which clients may sign in to each app, legacy authentication clients among them, in the app's sign-in policy, which this collector does not read."
)

// markMFARequirementUnread gives the normalized MFA requirement values a gap
// when ToIDPPosture left them out for app sign-in policies. The gap is
// not_read when an app has one, and the app list's own gap when the list
// could not be read. The count gets one only at the audit level and above.
func (c *Collector) markMFARequirementUnread(p PolicyConfig, level componentsdk.Level) {
	var pointers []string
	if p.mfaRequirementUnread() {
		pointers = append(pointers, "/policy/mfa_required")
	}
	if p.mfaCoverageUnread() {
		pointers = append(pointers, "/policy/mfa_required_coverage_pct")
		if level.AtLeast(componentsdk.LevelAudit) {
			pointers = append(pointers, "/policy/mfa_required_user_count")
		}
	}
	for _, pointer := range pointers {
		at := componentsdk.Location{Path: idpPosturePath, Pointer: pointer}
		if p.appsErr != nil {
			c.gaps.rec.NotCollected(at, p.appsErr, gapOptions(p.appsErr)...)
			continue
		}
		c.gaps.rec.NotCollectedCode(at, componentsdk.CodeNotRead, appSignInMFA)
	}
}

// markIDPPostureLeftOut gives each value in idpPostureLeftOut its gap. The
// counts get one only at the audit level and above, where the artifact has
// counts.
func (c *Collector) markIDPPostureLeftOut(level componentsdk.Level) {
	for _, u := range idpPostureLeftOut {
		if u.audit && !level.AtLeast(componentsdk.LevelAudit) {
			continue
		}
		c.gaps.rec.NotCollectedCode(componentsdk.Location{Path: idpPosturePath, Pointer: u.pointer}, u.code, u.reason)
	}
}

func floatPtr(v *int) *float64 {
	if v == nil {
		return nil
	}
	f := float64(*v)
	return &f
}

// present returns whether a population of count has any members, or nil
// when count could not be read.
func present(count *int) *bool {
	if count == nil {
		return nil
	}
	return boolPtr(*count > 0)
}

func isTrue(b *bool) bool {
	return b != nil && *b
}

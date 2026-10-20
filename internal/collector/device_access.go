package collector

import (
	"context"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// deviceAccessMetricsCollector holds device access enforcement state.
type deviceAccessMetricsCollector struct {
	assuranceErr                error // the device assurance policies could not be read
	managedDeviceRequiredUsers  int
	managedDeviceRequiredAdmins int
	policies                    []okta.DeviceAssurancePolicy
}

// deviceAssurancePolicySummary projects an okta.DeviceAssurancePolicy onto its
// audit-level summary row, flattening the per-platform assurance settings.
func deviceAssurancePolicySummary(dap okta.DeviceAssurancePolicy) DeviceAssurancePolicySummary {
	summary := DeviceAssurancePolicySummary{
		Name:                dap.Name,
		Platform:            dap.Platform,
		Status:              dap.Status,
		DiskEncryptionReq:   dap.DiskEncryptionType != nil && len(dap.DiskEncryptionType.Include) > 0,
		ScreenLockReq:       dap.ScreenLockType != nil && len(dap.ScreenLockType.Include) > 0,
		JailbreakProtection: dap.Jailbreak != nil,
	}
	if dap.OSVersion != nil {
		summary.MinOSVersion = dap.OSVersion.Minimum
	}
	return summary
}

func (c *Collector) collectDeviceAccessMetrics(
	ctx context.Context,
	userMetrics *userMetricsCollector,
	privileged *privilegedMetricsCollector,
	policy *policyMetricsCollector,
) *deviceAccessMetricsCollector {
	metrics := &deviceAccessMetricsCollector{}

	// The managed-device values derive from sign-on rules, so a failed
	// device-assurance read (a missing okta.deviceAssurance.read scope or the
	// feature not enabled) leaves out only the assurance values.
	deviceAssurancePolicies, err := c.client.FetchDeviceAssurancePolicies(ctx)
	if err != nil {
		metrics.assuranceErr = c.warnSurface("device assurance policies", "okta.deviceAssurance.read", err)
	}
	metrics.policies = deviceAssurancePolicies

	if firstError(userMetrics.err, policy.signOnErr, policy.groupsErr) != nil {
		return metrics
	}

	// Evaluate per-user coverage
	c.status("Evaluating device access coverage...")
	for _, user := range userMetrics.users {
		if user.Status == StatusDeprovisioned {
			continue
		}
		if userCoveredByManagedDeviceRequirement(user.ID, policy.signOnPolicies, policy.groupMembers) {
			metrics.managedDeviceRequiredUsers++

			if _, isAdmin := privileged.privilegedUserIDs[user.ID]; isAdmin {
				metrics.managedDeviceRequiredAdmins++
			}
		}
	}

	return metrics
}

// fillDeviceAccess writes the device access metrics into the posture,
// leaving out with a gap each value the reads it needs did not give.
func (c *Collector) fillDeviceAccess(p *OrgPosture, users *userMetricsCollector, privileged *privilegedMetricsCollector, policy *policyMetricsCollector, m *deviceAccessMetricsCollector, level componentsdk.Level) {
	audit := level.AtLeast(componentsdk.LevelAudit)
	if m.assuranceErr != nil {
		c.gaps.notCollected(m.assuranceErr, "/device_access/device_assurance_policies_count")
		if audit {
			c.gaps.notCollected(m.assuranceErr, "/device_access/policies")
		}
	} else {
		p.DeviceAccess.DeviceAssurancePoliciesCount = intPtr(len(m.policies))
		if audit {
			p.DeviceAccess.Policies = make([]DeviceAssurancePolicySummary, 0, len(m.policies))
			for _, dap := range m.policies {
				p.DeviceAccess.Policies = append(p.DeviceAccess.Policies, deviceAssurancePolicySummary(dap))
			}
		}
	}

	if policy.signOnErr != nil {
		c.gaps.notCollected(policy.signOnErr, "/device_access/managed_device_required")
	} else {
		p.DeviceAccess.ManagedDeviceRequired = boolPtr(anySignOnRuleRequiresManagedDevice(policy.signOnPolicies))
	}

	coverageErr := firstError(users.err, policy.signOnErr, policy.groupsErr)
	if coverageErr != nil {
		c.gaps.notCollected(coverageErr, "/device_access/managed_device_required_coverage_pct", "/device_access/managed_device_required_users_count")
	} else {
		p.DeviceAccess.ManagedDeviceRequiredCoveragePct = percent(m.managedDeviceRequiredUsers, users.totalUsers)
		p.DeviceAccess.ManagedDeviceRequiredUsersCount = intPtr(m.managedDeviceRequiredUsers)
	}

	forAdmins := []string{"/device_access/managed_device_required_for_admins", "/device_access/managed_device_required_admins_count"}
	switch {
	case privileged.err != nil:
		c.gaps.notCollected(privileged.err, forAdmins...)
	case coverageErr != nil:
		c.gaps.notCollected(coverageErr, forAdmins...)
	case privileged.rolesFailed > 0:
		c.gaps.partial(privileged.rolesFailed, privileged.firstRolesErr, forAdmins...)
	default:
		p.DeviceAccess.ManagedDeviceRequiredAdminsCount = intPtr(m.managedDeviceRequiredAdmins)
		if privileged.privilegedUsersCount > 0 {
			p.DeviceAccess.ManagedDeviceRequiredForAdmins = boolPtr(m.managedDeviceRequiredAdmins == privileged.privilegedUsersCount)
		}
	}
}

// DeviceAccessMetrics contains device access enforcement posture. A value is
// null when a read it needs failed; managed_device_required_coverage_pct is
// also null when the org has no users, and managed_device_required_for_admins
// when it has no privileged users.
//
// Audit adds the per-device-assurance-policy summary.
type DeviceAccessMetrics struct {
	ManagedDeviceRequired            *bool `json:"managed_device_required"`              // Whether any sign-on policy rule requires managed devices
	ManagedDeviceRequiredCoveragePct *int  `json:"managed_device_required_coverage_pct"` // % of users covered by a managed device requirement
	ManagedDeviceRequiredUsersCount  *int  `json:"managed_device_required_users_count"`  // Users covered by a managed device requirement
	ManagedDeviceRequiredForAdmins   *bool `json:"managed_device_required_for_admins"`   // Whether all privileged users are covered by a managed device requirement
	ManagedDeviceRequiredAdminsCount *int  `json:"managed_device_required_admins_count"` // Privileged users covered by a managed device requirement
	DeviceAssurancePoliciesCount     *int  `json:"device_assurance_policies_count"`      // Number of device assurance policies defined

	// Audit-level field.
	Policies []DeviceAssurancePolicySummary `json:"policies,omitempty"`
}

// DeviceAssurancePolicySummary is a per-device-assurance-policy summary (audit+).
// The requirement flags are a best-effort flattening of Okta's per-platform
// assurance settings.
type DeviceAssurancePolicySummary struct {
	Name                string `json:"name"`
	Platform            string `json:"platform"`
	Status              string `json:"status,omitempty"`
	MinOSVersion        string `json:"min_os_version,omitempty"`
	DiskEncryptionReq   bool   `json:"disk_encryption_required"`
	ScreenLockReq       bool   `json:"screen_lock_required"`
	JailbreakProtection bool   `json:"jailbreak_protection"`
}

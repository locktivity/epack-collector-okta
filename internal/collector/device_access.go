package collector

import (
	"context"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// deviceAccessMetricsCollector holds device access enforcement state.
type deviceAccessMetricsCollector struct {
	managedDeviceRequired            bool
	managedDeviceRequiredUsers       int
	managedDeviceRequiredAdmins      int
	deviceAssurancePoliciesCount     int
	managedDeviceRequiredCoveragePct int
	managedDeviceRequiredForAdmins   bool
	policies                         []DeviceAssurancePolicySummary // Audit-level per-policy rows
}

// toDeviceAccess maps the collected device-access state onto the output DTO.
func (m *deviceAccessMetricsCollector) toDeviceAccess() DeviceAccessMetrics {
	return DeviceAccessMetrics{
		ManagedDeviceRequired:            m.managedDeviceRequired,
		ManagedDeviceRequiredCoveragePct: m.managedDeviceRequiredCoveragePct,
		ManagedDeviceRequiredForAdmins:   m.managedDeviceRequiredForAdmins,
		DeviceAssurancePoliciesCount:     m.deviceAssurancePoliciesCount,
		Policies:                         m.policies,
	}
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
	privilegedUserIDs map[string]struct{},
	signOnPolicies []scopedPolicy,
	groupMembers groupMembership,
	level componentsdk.Level,
) (*deviceAccessMetricsCollector, error) {
	metrics := &deviceAccessMetricsCollector{}

	// Fetch device assurance policies count. Degrade on failure (e.g. missing
	// okta.deviceAssurance.read scope or feature not enabled): the managed-device
	// computation below derives from sign-on rules and is still useful.
	c.status("Checking device assurance policies...")
	deviceAssurancePolicies, err := c.client.FetchDeviceAssurancePolicies(ctx)
	if err != nil {
		c.warnSurface("device assurance policies", "okta.deviceAssurance.read", err)
		deviceAssurancePolicies = nil
	}
	metrics.deviceAssurancePoliciesCount = len(deviceAssurancePolicies)

	if level.AtLeast(componentsdk.LevelAudit) {
		metrics.policies = make([]DeviceAssurancePolicySummary, 0, len(deviceAssurancePolicies))
		for _, dap := range deviceAssurancePolicies {
			metrics.policies = append(metrics.policies, deviceAssurancePolicySummary(dap))
		}
	}

	// Check if any sign-on rule requires managed devices
	metrics.managedDeviceRequired = anySignOnRuleRequiresManagedDevice(signOnPolicies)

	// Evaluate per-user coverage
	c.status("Evaluating device access coverage...")
	totalUsers := 0
	totalAdmins := len(privilegedUserIDs)
	for _, user := range userMetrics.users {
		if user.Status == StatusDeprovisioned {
			continue
		}
		totalUsers++

		if userCoveredByManagedDeviceRequirement(user.ID, signOnPolicies, groupMembers) {
			metrics.managedDeviceRequiredUsers++

			if _, isAdmin := privilegedUserIDs[user.ID]; isAdmin {
				metrics.managedDeviceRequiredAdmins++
			}
		}
	}

	metrics.managedDeviceRequiredCoveragePct = percent(metrics.managedDeviceRequiredUsers, totalUsers)
	metrics.managedDeviceRequiredForAdmins = totalAdmins > 0 && metrics.managedDeviceRequiredAdmins == totalAdmins

	return metrics, nil
}

// DeviceAccessMetrics contains device access enforcement posture.
//
// Audit adds the per-device-assurance-policy summary.
type DeviceAccessMetrics struct {
	ManagedDeviceRequired            bool `json:"managed_device_required"`              // Whether any sign-on policy rule requires managed devices
	ManagedDeviceRequiredCoveragePct int  `json:"managed_device_required_coverage_pct"` // % of users covered by a managed device requirement
	ManagedDeviceRequiredForAdmins   bool `json:"managed_device_required_for_admins"`   // Whether all privileged users are covered by a managed device requirement
	DeviceAssurancePoliciesCount     int  `json:"device_assurance_policies_count"`      // Number of device assurance policies defined

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

package collector

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// privilegedMetricsCollector holds privileged access counts and MFA coverage.
type privilegedMetricsCollector struct {
	err                           error // the user list or the role assignees could not be read
	rolesFailed                   int   // role-assigned users whose roles could not be read
	firstRolesErr                 error
	mfaUnknown                    int // privileged users whose factors could not be read
	firstMFAErr                   error
	privilegedUsersCount          int
	superAdminCount               int
	standingPrivilegedUsersCount  int
	privilegedMFAEnrolledCount    int
	privilegedPhishingFactorCount int
	privilegedUserIDs             map[string]struct{} // Set of privileged user IDs for reuse
	inventory                     []PrivilegedUser    // Audit-level per-privileged-user rows
}

func (c *Collector) collectPrivilegedMetrics(ctx context.Context, userMetrics *userMetricsCollector, level componentsdk.Level) *privilegedMetricsCollector {
	metrics := &privilegedMetricsCollector{
		privilegedUserIDs: make(map[string]struct{}),
	}
	if userMetrics.err != nil {
		// Role assignments name users by ID; without the user list their
		// status and login are unknown.
		metrics.err = userMetrics.err
		return metrics
	}

	// Kept in the order Okta lists them, so the inventory and the order of
	// the per-user calls are stable.
	var roleAssignedUserIDs []string
	seen := make(map[string]struct{})
	err := c.client.FetchUsersWithRoleAssignments(ctx, func(users []okta.RoleAssignedUser) error {
		for _, user := range users {
			if _, dup := seen[user.ID]; dup {
				continue
			}
			seen[user.ID] = struct{}{}
			roleAssignedUserIDs = append(roleAssignedUserIDs, user.ID)
		}
		return nil
	})
	if err != nil {
		// Reading admin-role assignments is privileged: Read-Only Administrator
		// cannot list them, so least-privilege service apps get a 403 here.
		// The privileged metrics are left out and a diagnostic names what to
		// grant.
		metrics.err = c.warnSurface("privileged access: failed to list admin-role assignments", "okta.roles.read", err)
		return metrics
	}

	total := int64(len(roleAssignedUserIDs))
	for i, userID := range roleAssignedUserIDs {
		c.progress(int64(i+1), total, fmt.Sprintf("Checking privileged roles for user %d of %d", i+1, total))

		user, ok := userMetrics.userByID[userID]
		if !ok {
			c.warn("privileged access: role-assigned user %s missing from user inventory; skipping", userID)
			continue
		}
		if user.Status == StatusDeprovisioned || user.Status == StatusSuspended {
			continue
		}

		roles, err := c.client.FetchUserRoleAssignments(ctx, userID)
		if err != nil {
			err = c.warnSurface(fmt.Sprintf("privileged access: failed to fetch roles for user %s", userID), "okta.roles.read", err)
			metrics.rolesFailed++
			if metrics.firstRolesErr == nil {
				metrics.firstRolesErr = err
			}
			continue
		}
		if len(roles) == 0 {
			continue
		}

		metrics.privilegedUsersCount++
		metrics.standingPrivilegedUsersCount++
		metrics.privilegedUserIDs[userID] = struct{}{}

		if factorErr, failed := userMetrics.factorErrs[userID]; failed {
			metrics.mfaUnknown++
			if metrics.firstMFAErr == nil {
				metrics.firstMFAErr = factorErr
			}
		} else {
			if userMetrics.hasMFAByUser[userID] {
				metrics.privilegedMFAEnrolledCount++
			}
			if userMetrics.hasPhishingByUser[userID] {
				metrics.privilegedPhishingFactorCount++
			}
		}
		if hasRoleType(roles, RoleTypeSuperAdmin) {
			metrics.superAdminCount++
		}

		if level.AtLeast(componentsdk.LevelAudit) {
			metrics.inventory = append(metrics.inventory, privilegedUserRow(user, roles, userMetrics, level))
		}
	}

	return metrics
}

// fillPrivileged writes the privileged access metrics into the posture,
// leaving out with a gap each value the reads it needs did not give.
func (c *Collector) fillPrivileged(p *OrgPosture, m *privilegedMetricsCollector, level componentsdk.Level) {
	audit := level.AtLeast(componentsdk.LevelAudit)
	counts := []string{
		"/privileged_access/privileged_users_count",
		"/privileged_access/super_admin_count",
		"/privileged_access/standing_privileged_users_count",
	}
	coverage := []string{
		"/privileged_access/privileged_mfa_coverage_pct",
		"/privileged_access/privileged_mfa_enrolled_count",
		"/privileged_access/privileged_phishing_resistant_pct",
		"/privileged_access/privileged_phishing_resistant_count",
	}
	switch {
	case m.err != nil:
		c.gaps.notCollected(m.err, append(counts, coverage...)...)
		if audit {
			c.gaps.notCollected(m.err, "/privileged_access/inventory")
		}
	case m.rolesFailed > 0:
		c.gaps.partial(m.rolesFailed, m.firstRolesErr, append(counts, coverage...)...)
		if audit {
			c.gaps.partial(m.rolesFailed, m.firstRolesErr, "/privileged_access/inventory")
		}
	default:
		p.PrivilegedAccess.PrivilegedUsersCount = intPtr(m.privilegedUsersCount)
		p.PrivilegedAccess.SuperAdminCount = intPtr(m.superAdminCount)
		p.PrivilegedAccess.StandingPrivilegedUsersCount = intPtr(m.standingPrivilegedUsersCount)
		if m.mfaUnknown > 0 {
			c.gaps.partial(m.mfaUnknown, m.firstMFAErr, coverage...)
		} else {
			p.PrivilegedAccess.PrivilegedMFACoveragePct = percent(m.privilegedMFAEnrolledCount, m.privilegedUsersCount)
			p.PrivilegedAccess.PrivilegedMFAEnrolledCount = intPtr(m.privilegedMFAEnrolledCount)
			p.PrivilegedAccess.PrivilegedPhishingResistantPct = percent(m.privilegedPhishingFactorCount, m.privilegedUsersCount)
			p.PrivilegedAccess.PrivilegedPhishingResistantCount = intPtr(m.privilegedPhishingFactorCount)
		}
		if audit {
			p.PrivilegedAccess.Inventory = m.inventory
			for i, row := range m.inventory {
				if row.factorsErr != nil {
					c.gaps.notCollected(row.factorsErr, rowPointer("/privileged_access/inventory", i, "has_active_mfa"),
						rowPointer("/privileged_access/inventory", i, "has_phishing_resistant_mfa"))
				}
			}
		}
	}
}

// privilegedUserRow builds the audit-level inventory row for a privileged user.
// Internal level adds the role-assignment source, the last-login timestamp,
// and the MFA flags the user's factors give, which are left out when their
// factors could not be read.
func privilegedUserRow(user okta.User, roles []okta.RoleAssignment, users *userMetricsCollector, level componentsdk.Level) PrivilegedUser {
	row := PrivilegedUser{
		Login: user.Profile.Login,
		Roles: roleNames(roles),
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.RoleAssignmentSource = roleAssignmentSource(roles)
		row.LastLoginAt = formatTime(user.LastLogin)
		if err, failed := users.factorErrs[user.ID]; failed {
			row.factorsErr = err
		} else {
			row.HasActiveMFA = boolPtr(users.hasMFAByUser[user.ID])
			row.HasPhishingResistantMFA = boolPtr(users.hasPhishingByUser[user.ID])
		}
	}
	return row
}

// roleNames returns the display name for each role assignment. Custom roles
// (type CUSTOM) surface their label; built-in roles surface their type.
func roleNames(roles []okta.RoleAssignment) []string {
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		if strings.EqualFold(r.Type, "CUSTOM") && r.Label != "" {
			names = append(names, r.Label)
		} else {
			names = append(names, r.Type)
		}
	}
	return names
}

// roleAssignmentSource summarizes how a user's admin roles are assigned: directly
// (USER), via group membership (GROUP), or both.
func roleAssignmentSource(roles []okta.RoleAssignment) string {
	hasDirect, hasGroup := false, false
	for _, r := range roles {
		switch strings.ToUpper(r.AssignmentType) {
		case "GROUP":
			hasGroup = true
		default:
			hasDirect = true
		}
	}
	switch {
	case hasDirect && hasGroup:
		return "mixed"
	case hasGroup:
		return "group"
	default:
		return "direct"
	}
}

// workflowsAdminRole is Okta's built-in Workflows Administrator role. Okta
// lists it with the custom roles because it is scoped to the built-in
// Workflows resource set.
const workflowsAdminRole = "WORKFLOWS_ADMIN"

// collectCustomRoles fetches the custom-admin-role inventory (Identity Governance
// feature). A 404 means the feature is not licensed; any other failure leaves
// the inventory out with a gap. Standard built-in roles are surfaced via the
// per-user inventory. Returns nil below audit level.
func (c *Collector) collectCustomRoles(ctx context.Context, level componentsdk.Level) []CustomRole {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	roles, err := c.client.ListIAMRoles(ctx)
	if err != nil {
		if okta.StatusCodeOf(err) == http.StatusNotFound {
			warning := c.warn("custom admin roles: not available (Okta Identity Governance not licensed)")
			c.gaps.notLicensed("/privileged_access/custom_roles", "custom admin roles need Okta Identity Governance", warning)
			return nil
		}
		err = c.warnSurface("custom admin roles", "okta.roles.read", err)
		c.gaps.notCollected(err, "/privileged_access/custom_roles")
		return nil
	}

	result := make([]CustomRole, 0, len(roles))
	for _, r := range roles {
		if r.ID == workflowsAdminRole {
			continue
		}
		row := CustomRole{Name: r.ID, Label: r.Label, Description: r.Description}
		if permissions, err := c.client.ListRolePermissions(ctx, r.ID); err != nil {
			err = c.warnSurface(fmt.Sprintf("custom admin role %s: failed to fetch permissions", r.Label), "okta.roles.read", err)
			c.gaps.notCollected(err, rowPointer("/privileged_access/custom_roles", len(result), "permission_count"))
		} else {
			row.PermissionCount = intPtr(len(permissions))
		}
		result = append(result, row)
	}
	return result
}

func hasRoleType(roles []okta.RoleAssignment, roleType string) bool {
	for _, role := range roles {
		if strings.EqualFold(role.Type, roleType) {
			return true
		}
	}
	return false
}

// PrivilegedAccessMetrics contains privileged account counts and MFA coverage.
// Each is null when the users, the role assignments, or (for the coverage
// percentages) the privileged users' factors could not be read, and a
// percentage is null when there are no privileged users.
//
// Audit adds the per-privileged-user inventory and the custom-admin-role
// inventory (Identity Governance feature; absent when not licensed).
type PrivilegedAccessMetrics struct {
	PrivilegedUsersCount             *int `json:"privileged_users_count"`
	SuperAdminCount                  *int `json:"super_admin_count"`
	StandingPrivilegedUsersCount     *int `json:"standing_privileged_users_count"`
	PrivilegedMFACoveragePct         *int `json:"privileged_mfa_coverage_pct"`
	PrivilegedMFAEnrolledCount       *int `json:"privileged_mfa_enrolled_count"`
	PrivilegedPhishingResistantPct   *int `json:"privileged_phishing_resistant_pct"`
	PrivilegedPhishingResistantCount *int `json:"privileged_phishing_resistant_count"`

	// Audit-level fields.
	Inventory   []PrivilegedUser `json:"inventory,omitempty"`
	CustomRoles []CustomRole     `json:"custom_roles,omitempty"`
}

// PrivilegedUser is a per-privileged-user inventory row (audit+).
//
// Internal adds the role-assignment source and per-user activity timestamps.
type PrivilegedUser struct {
	Login string   `json:"login"`
	Roles []string `json:"roles"` // Assigned admin role names (e.g. SUPER_ADMIN)

	// Internal-level fields.
	RoleAssignmentSource    string `json:"role_assignment_source,omitempty"` // direct / group / mixed
	LastLoginAt             string `json:"last_login_at,omitempty"`
	HasActiveMFA            *bool  `json:"has_active_mfa,omitempty"`
	HasPhishingResistantMFA *bool  `json:"has_phishing_resistant_mfa,omitempty"`

	factorsErr error
}

// CustomRole is a custom administrator role (audit+, Identity Governance feature).
type CustomRole struct {
	Name            string `json:"name"`
	Label           string `json:"label"`
	Description     string `json:"description,omitempty"`
	PermissionCount *int   `json:"permission_count"`
}

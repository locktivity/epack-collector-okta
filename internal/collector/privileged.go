package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// privilegedMetricsCollector holds privileged access counts and MFA coverage.
type privilegedMetricsCollector struct {
	privilegedUsersCount           int
	superAdminCount                int
	standingPrivilegedUsersCount   int
	privilegedMFAEnrolledCount     int
	privilegedPhishingFactorCount  int
	privilegedMFACoveragePct       int
	privilegedPhishingResistantPct int
	privilegedUserIDs              map[string]struct{} // Set of privileged user IDs for reuse
	inventory                      []PrivilegedUser    // Audit-level per-privileged-user rows
	customRoles                    []CustomRole        // Audit-level custom admin roles
}

// toPrivilegedAccess maps the collected privileged-access state onto the output DTO.
func (m *privilegedMetricsCollector) toPrivilegedAccess() PrivilegedAccessMetrics {
	return PrivilegedAccessMetrics{
		PrivilegedUsersCount:           m.privilegedUsersCount,
		SuperAdminCount:                m.superAdminCount,
		StandingPrivilegedUsersCount:   m.standingPrivilegedUsersCount,
		PrivilegedMFACoveragePct:       m.privilegedMFACoveragePct,
		PrivilegedPhishingResistantPct: m.privilegedPhishingResistantPct,
		Inventory:                      m.inventory,
		CustomRoles:                    m.customRoles,
	}
}

func (c *Collector) collectPrivilegedMetrics(ctx context.Context, userMetrics *userMetricsCollector, level componentsdk.Level) (*privilegedMetricsCollector, error) {
	metrics := &privilegedMetricsCollector{
		privilegedUserIDs: make(map[string]struct{}),
	}
	roleAssignedUserIDs := make(map[string]struct{})

	err := c.client.FetchUsersWithRoleAssignments(ctx, func(users []okta.RoleAssignedUser) error {
		for _, user := range users {
			roleAssignedUserIDs[user.ID] = struct{}{}
		}
		return nil
	})
	if err != nil {
		// Reading admin-role assignments is privileged: Read-Only Administrator
		// cannot list them, so least-privilege service apps get a 403 here.
		// Degrade rather than fail the whole run; the surface emits zeros and a
		// diagnostic names what to grant.
		if okta.StatusCodeOf(err) == 403 {
			c.warn("privileged access: cannot list admin-role assignments (403); the service app's admin role cannot read role assignments")
		} else {
			c.warn("privileged access: failed to list admin-role assignments: %v", err)
		}
		return metrics, nil
	}

	total := int64(len(roleAssignedUserIDs))
	current := int64(0)
	for userID := range roleAssignedUserIDs {
		current++
		c.progress(current, total, fmt.Sprintf("Checking privileged roles for user %d of %d", current, total))

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
			c.warn("privileged access: failed to fetch roles for user %s: %v", userID, err)
			continue
		}
		if len(roles) == 0 {
			continue
		}

		metrics.privilegedUsersCount++
		metrics.standingPrivilegedUsersCount++
		metrics.privilegedUserIDs[userID] = struct{}{}

		if userMetrics.hasMFAByUser[userID] {
			metrics.privilegedMFAEnrolledCount++
		}
		if userMetrics.hasPhishingByUser[userID] {
			metrics.privilegedPhishingFactorCount++
		}
		if hasRoleType(roles, RoleTypeSuperAdmin) {
			metrics.superAdminCount++
		}

		if level.AtLeast(componentsdk.LevelAudit) {
			metrics.inventory = append(metrics.inventory, privilegedUserRow(user, roles, level))
		}
	}

	metrics.privilegedMFACoveragePct = percent(metrics.privilegedMFAEnrolledCount, metrics.privilegedUsersCount)
	metrics.privilegedPhishingResistantPct = percent(metrics.privilegedPhishingFactorCount, metrics.privilegedUsersCount)

	if level.AtLeast(componentsdk.LevelAudit) {
		metrics.customRoles = c.collectCustomRoles(ctx)
	}

	return metrics, nil
}

// privilegedUserRow builds the audit-level inventory row for a privileged user.
// Internal level adds the role-assignment source and last-login timestamp.
func privilegedUserRow(user okta.User, roles []okta.RoleAssignment, level componentsdk.Level) PrivilegedUser {
	row := PrivilegedUser{
		Login: user.Profile.Login,
		Roles: roleNames(roles),
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.RoleAssignmentSource = roleAssignmentSource(roles)
		row.LastLoginAt = formatTime(user.LastLogin)
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

// collectCustomRoles fetches the custom-admin-role inventory (Identity Governance
// feature). A 404 means the feature is not licensed and a 403 means the scope is
// missing; both emit a diagnostic and return nil so built-in roles still emit
// cleanly. Standard built-in roles are surfaced via the per-user inventory.
func (c *Collector) collectCustomRoles(ctx context.Context) []CustomRole {
	roles, err := c.client.ListIAMRoles(ctx)
	if err != nil {
		switch okta.StatusCodeOf(err) {
		case 404:
			c.warn("custom admin roles: not available (Okta Identity Governance not licensed)")
		case 403:
			c.warn("custom admin roles: access denied (missing scope okta.roles.read?)")
		default:
			c.warn("custom admin roles: %s", err)
		}
		return nil
	}

	result := make([]CustomRole, 0, len(roles))
	for _, r := range roles {
		row := CustomRole{Name: r.ID, Label: r.Label, Description: r.Description}
		if permissions, err := c.client.ListRolePermissions(ctx, r.ID); err != nil {
			c.warn("custom admin role %s: failed to fetch permissions: %s", r.Label, err)
		} else {
			row.PermissionCount = len(permissions)
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
//
// Audit adds the per-privileged-user inventory and the custom-admin-role
// inventory (Identity Governance feature; absent when not licensed).
type PrivilegedAccessMetrics struct {
	PrivilegedUsersCount           int `json:"privileged_users_count"`
	SuperAdminCount                int `json:"super_admin_count"`
	StandingPrivilegedUsersCount   int `json:"standing_privileged_users_count"`
	PrivilegedMFACoveragePct       int `json:"privileged_mfa_coverage_pct"`
	PrivilegedPhishingResistantPct int `json:"privileged_phishing_resistant_pct"`

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
	RoleAssignmentSource string `json:"role_assignment_source,omitempty"` // direct / group / mixed
	LastLoginAt          string `json:"last_login_at,omitempty"`
	LastAdminActionAt    string `json:"last_admin_action_at,omitempty"` // From system log, if that surface ran
}

// CustomRole is a custom administrator role (audit+, Identity Governance feature).
type CustomRole struct {
	Name            string `json:"name"`
	Label           string `json:"label"`
	Description     string `json:"description,omitempty"`
	PermissionCount int    `json:"permission_count"`
}

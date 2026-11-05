package collector

import (
	"context"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// OrgSettings is the org-settings surface.
//
// Collected at audit and above; trust omits it.
//
// Audit: org identity + status + self-service-account-recovery flag.
// Internal: + system-notification email recipient logins (admin contacts).
//
// Note: brand-custom-domain, OAuth-app-creation-policy, and support-impersonation
// flags are not exposed by the public /api/v1/org, /preferences, or /contacts
// endpoints, so they are omitted rather than emitted with a fabricated value.
// Revisit if Okta surfaces them via API.
type OrgSettings struct {
	Subdomain string `json:"subdomain,omitempty"`
	Status    string `json:"status,omitempty"`

	// Audit-level field: true when the password policy rule that applies to
	// at least one person lets them reset their password or unlock their
	// account themselves.
	SelfServiceRecoveryEnabled *bool `json:"self_service_recovery_enabled,omitempty"`

	// Internal-level field.
	NotificationContactLogins []string `json:"notification_contact_logins,omitempty"`
}

func (c *Collector) collectOrgSettings(ctx context.Context, level componentsdk.Level, users *userMetricsCollector, policyMetrics *policyMetricsCollector) *OrgSettings {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}
	org, err := c.client.FetchOrgSettings(ctx)
	if err != nil {
		err = c.warnSurface("org settings", "okta.orgs.read", err)
		c.gaps.notCollected(err, "/org_settings")
		return nil
	}

	out := &OrgSettings{Subdomain: org.Subdomain, Status: org.Status}

	if recovery, err := c.selfServiceRecovery(ctx, users, policyMetrics.groupMembers); err != nil {
		c.gaps.notCollected(err, "/org_settings/self_service_recovery_enabled")
	} else {
		out.SelfServiceRecoveryEnabled = &recovery
	}

	if !level.AtLeast(componentsdk.LevelInternal) {
		return out
	}

	contacts, err := c.client.FetchOrgContactUsers(ctx)
	if err != nil {
		err = c.warnSurface("org contacts", "okta.orgs.read", err)
		c.gaps.notCollected(err, "/org_settings/notification_contact_logins")
		return out
	}
	if users.err != nil {
		c.gaps.notCollected(users.err, "/org_settings/notification_contact_logins")
		return out
	}
	// Okta names each contact by user ID; a contact missing from the user
	// list, such as a deprovisioned user, has no login to show.
	logins := make([]string, 0, len(contacts))
	for _, contact := range contacts {
		if user, ok := users.userByID[contact.UserID]; ok {
			logins = append(logins, user.Profile.Login)
		}
	}
	out.NotificationContactLogins = logins

	return out
}

// selfServiceRecovery reports whether anyone can reset their own password or
// unlock their own account. Okta applies the first password policy that
// matches a person, and in it the first rule whose conditions are met. A rule
// lower down can then apply to no one. known holds the group members the
// policy step read, and they are not read again.
func (c *Collector) selfServiceRecovery(ctx context.Context, users *userMetricsCollector, known groupMembership) (bool, error) {
	policies, err := c.fetchActivePoliciesWithRules(ctx, PolicyTypePassword)
	if err != nil {
		return false, c.warnSurface("password policies", "okta.policies.read", err)
	}
	if users.err != nil {
		return false, users.err
	}
	members, err := c.fetchGroupMembersForPolicies(ctx, policies, known)
	if err != nil {
		return false, c.warnSurface("password policy group memberships", "okta.groups.read", err)
	}
	for _, user := range users.users {
		if user.Status == StatusDeprovisioned {
			continue
		}
		if firstMatchingRuleDecides(user.ID, policies, members, anyRule, recoveryRuleDecision) {
			return true, nil
		}
	}
	return false, nil
}

// recoveryRuleDecision gives the self-service recovery result for a password
// rule that matches the person. A rule that denies recovery to only some
// sign-ins, such as those from one network zone, leaves the person's other
// sign-ins to the next rule.
func recoveryRuleDecision(r okta.PolicyRule) (covered, decided bool) {
	if allows(r.Actions.SelfServicePasswordReset) || allows(r.Actions.SelfServiceUnlock) {
		return true, true
	}
	return false, !limitedToSomeSignIns(r.Conditions)
}

func allows(action *okta.RuleAccess) bool {
	return action != nil && action.Access == AccessAllow
}

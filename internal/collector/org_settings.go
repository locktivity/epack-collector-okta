package collector

import (
	"context"

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

	// Audit-level field.
	SelfServiceRecoveryEnabled *bool `json:"self_service_recovery_enabled,omitempty"`

	// Internal-level field.
	NotificationContactLogins []string `json:"notification_contact_logins,omitempty"`
}

func (c *Collector) collectOrgSettings(ctx context.Context, level componentsdk.Level, users *userMetricsCollector) *OrgSettings {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}
	c.status("Collecting org settings...")

	org, err := c.client.FetchOrgSettings(ctx)
	if err != nil {
		c.warnSurface("org settings", "okta.orgs.read", err)
		c.gaps.notCollected(err, "/org_settings")
		return nil
	}

	out := &OrgSettings{Subdomain: org.Subdomain, Status: org.Status}

	if prefs, err := c.client.FetchOrgPreferences(ctx); err != nil {
		c.warn("org preferences: %s", err)
		c.gaps.notCollected(err, "/org_settings/self_service_recovery_enabled")
	} else {
		recovery := prefs.SelfServiceUnlock
		out.SelfServiceRecoveryEnabled = &recovery
	}

	if !level.AtLeast(componentsdk.LevelInternal) {
		return out
	}

	contacts, err := c.client.FetchOrgContactUsers(ctx)
	if err != nil {
		c.warn("org contacts: %s", err)
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

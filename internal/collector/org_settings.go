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

func (c *Collector) collectOrgSettings(ctx context.Context, level componentsdk.Level) *OrgSettings {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}
	c.status("Collecting org settings...")

	org, err := c.client.FetchOrgSettings(ctx)
	if err != nil {
		c.warnSurface("org settings", "okta.orgs.read", err)
		return nil
	}
	if org == nil {
		return nil
	}

	out := &OrgSettings{Subdomain: org.Subdomain, Status: org.Status}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out
	}

	if prefs, err := c.client.FetchOrgPreferences(ctx); err != nil {
		c.warn("org preferences: %s", err)
	} else {
		recovery := prefs.SelfServiceUnlock
		out.SelfServiceRecoveryEnabled = &recovery
	}

	if !level.AtLeast(componentsdk.LevelInternal) {
		return out
	}

	if contacts, err := c.client.FetchOrgContactUsers(ctx); err != nil {
		c.warn("org contacts: %s", err)
		out.NotificationContactLogins = []string{}
	} else {
		logins := make([]string, 0, len(contacts))
		for _, contact := range contacts {
			logins = append(logins, contact.Login)
		}
		out.NotificationContactLogins = logins
	}

	return out
}

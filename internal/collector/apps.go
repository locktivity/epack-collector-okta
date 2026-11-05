package collector

import (
	"context"
	"fmt"
	"slices"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// appMetricsCollector holds intermediate app collection state.
type appMetricsCollector struct {
	err                   error // the app list could not be read
	totalApps             int
	ssoApps               int
	provisioningEnabled   int
	deprovisioningEnabled int
	inventory             []App // Audit-level per-app rows
	inventoryTruncated    bool
	inventoryDropped      int
	// appSignInPolicies is set when an active app has an app sign-in policy.
	appSignInPolicies bool
}

func (c *Collector) collectAppMetrics(ctx context.Context, level componentsdk.Level) *appMetricsCollector {
	var apps []okta.Application
	err := c.client.FetchApplications(ctx, func(page []okta.Application) error {
		apps = append(apps, page...)
		c.status(fmt.Sprintf("Found %d applications...", len(apps)))
		return nil
	})
	if err != nil {
		return &appMetricsCollector{err: c.warnSurface("applications", "okta.apps.read", err)}
	}

	metrics := &appMetricsCollector{}
	for _, app := range apps {
		c.processApp(app, metrics, level)
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		metrics.inventory, metrics.inventoryDropped, metrics.inventoryTruncated = Truncate(metrics.inventory, AppsCap, func(a, b App) bool {
			aActive := a.Status == StatusActive
			bActive := b.Status == StatusActive
			if aActive != bActive {
				return aActive
			}
			return a.Label < b.Label
		})
		if metrics.inventoryTruncated {
			c.warn("apps: inventory truncated to %d (dropped %d)", AppsCap, metrics.inventoryDropped)
		}
	}

	return metrics
}

// fillApps writes the app metrics into the posture, or leaves them out with a
// gap when the app list could not be read.
func (c *Collector) fillApps(p *OrgPosture, m *appMetricsCollector, level componentsdk.Level) {
	audit := level.AtLeast(componentsdk.LevelAudit)
	if m.err != nil {
		c.gaps.notCollected(m.err, "/apps/total_count", "/apps/sso_count", "/apps/provisioning_enabled", "/apps/provisioning_enabled_count",
			"/apps/deprovisioning_enabled", "/apps/deprovisioning_enabled_count", "/posture/sso_coverage")
		if audit {
			c.gaps.notCollected(m.err, "/apps/inventory")
		}
		return
	}
	p.Apps.TotalCount = intPtr(m.totalApps)
	p.Apps.ProvisioningEnabled = percent(m.provisioningEnabled, m.totalApps)
	p.Apps.ProvisioningEnabledCount = intPtr(m.provisioningEnabled)
	p.Apps.DeprovisioningEnabled = percent(m.deprovisioningEnabled, m.totalApps)
	p.Apps.DeprovisioningEnabledCount = intPtr(m.deprovisioningEnabled)
	p.Posture.SSOCoverage = percent(m.ssoApps, m.totalApps)
	p.Apps.SSOCount = intPtr(m.ssoApps)
	if audit {
		p.Apps.Inventory = m.inventory
		p.Apps.InventoryTruncated = m.inventoryTruncated
		p.Apps.InventoryDropped = m.inventoryDropped
	}
}

// processApp processes a single application and updates metrics.
// Deactivating an app removes every user's access to it, so an INACTIVE app
// is left out of the counts. So are Okta's own default apps and API service
// apps. Each of them stays in the inventory. An active app with an app
// sign-in policy sets appSignInPolicies, even when it is one of Okta's own.
func (c *Collector) processApp(app okta.Application, metrics *appMetricsCollector, level componentsdk.Level) {
	service := isServiceApp(app)
	sso := isSSO(app.SignOnMode) && !service
	hasProvisioning, hasDeprovisioning := checkProvisioningFeatures(app.Features)
	if app.Status != AppStatusInactive && app.Links.AccessPolicy != nil && app.Links.AccessPolicy.Href != "" {
		metrics.appSignInPolicies = true
	}
	if app.Status != AppStatusInactive && !isOktaDefaultApp(app) && !service {
		metrics.totalApps++
		if sso {
			metrics.ssoApps++
		}
		if hasProvisioning {
			metrics.provisioningEnabled++
		}
		if hasDeprovisioning {
			metrics.deprovisioningEnabled++
		}
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		kind := appType(app.SignOnMode)
		if service {
			kind = AppTypeService
		}
		metrics.inventory = append(metrics.inventory, App{
			Label:                  app.Label,
			Name:                   app.Name,
			Type:                   kind,
			SignOnMode:             app.SignOnMode,
			Status:                 app.Status,
			SSOConfigured:          sso,
			ProvisioningConfigured: hasProvisioning,
		})
	}
}

// appType maps an Okta sign-on mode to a coarse app type (SAML / OIDC / SWA /
// BOOKMARK). An API service app is AppTypeService instead.
func appType(signOnMode string) string {
	switch signOnMode {
	case SignOnModeSAML20, SignOnModeSAML11, SignOnModeWSFederation:
		return "SAML"
	case SignOnModeOIDC:
		return "OIDC"
	case "BOOKMARK":
		return "BOOKMARK"
	default:
		// BROWSER_PLUGIN, SECURE_PASSWORD_STORE, AUTO_LOGIN, etc. are SWA apps.
		return "SWA"
	}
}

// oktaDefaultAppLabels are the apps Okta puts in every org and maintains
// itself. Only a Super Admin can see them, so counting them would make the
// app counts depend on the collector's admin role.
// https://support.okta.com/help/s/article/Admin-user-unable-to-manage-default-Okta-Dashboard-Okta-Browser-Plugin-and-Okta-Admin-Console-applications
var oktaDefaultAppLabels = []string{"Okta Admin Console", "Okta Dashboard", "Okta Browser Plugin"}

// isOktaDefaultApp reports whether the app is one of Okta's default apps.
func isOktaDefaultApp(app okta.Application) bool {
	return slices.Contains(oktaDefaultAppLabels, app.Label)
}

// isServiceApp reports whether the app is an API service app, whose only
// grant is client credentials. That grant is for apps with no end user.
// https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/
func isServiceApp(app okta.Application) bool {
	grants := app.Settings.OAuthClient.GrantTypes
	if app.SignOnMode != SignOnModeOIDC || len(grants) == 0 {
		return false
	}
	for _, grant := range grants {
		if grant != "client_credentials" {
			return false
		}
	}
	return true
}

// isSSO checks if the sign-on mode is an SSO protocol.
func isSSO(mode string) bool {
	switch mode {
	case SignOnModeSAML20, SignOnModeSAML11, SignOnModeOIDC, SignOnModeWSFederation:
		return true
	}
	return false
}

// checkProvisioningFeatures checks app features for provisioning capabilities.
func checkProvisioningFeatures(features []string) (provisioning, deprovisioning bool) {
	for _, feature := range features {
		switch feature {
		case FeaturePushNewUsers, FeatureImportNewUsers:
			provisioning = true
		case FeaturePushUserDeactivation:
			deprovisioning = true
		}
	}
	return
}

// AppMetrics contains application lifecycle percentages (all 0-100). Each is
// null when the app list could not be read or the org has no apps the counts
// include. Inactive apps, Okta's default apps and API service apps are left
// out of the counts and percentages.
//
// Audit adds the per-app inventory, which includes inactive apps.
type AppMetrics struct {
	TotalCount                 *int `json:"total_count"`                  // Apps the counts include, which the app percentages are shares of
	SSOCount                   *int `json:"sso_count"`                    // Apps using SSO (SAML/OIDC/WS-Fed)
	ProvisioningEnabled        *int `json:"provisioning_enabled"`         // % apps with auto-provisioning
	ProvisioningEnabledCount   *int `json:"provisioning_enabled_count"`   // Apps with auto-provisioning
	DeprovisioningEnabled      *int `json:"deprovisioning_enabled"`       // % apps with auto-deprovisioning
	DeprovisioningEnabledCount *int `json:"deprovisioning_enabled_count"` // Apps with auto-deprovisioning

	// Audit-level field.
	Inventory          []App `json:"inventory,omitempty"`
	InventoryTruncated bool  `json:"inventory_truncated,omitempty"`
	InventoryDropped   int   `json:"inventory_dropped,omitempty"`
}

// App is a per-app inventory row (audit+).
type App struct {
	Label                  string `json:"label"`
	Name                   string `json:"name"`
	Type                   string `json:"type"` // SAML / OIDC / SWA / BOOKMARK / SERVICE
	SignOnMode             string `json:"sign_on_mode"`
	Status                 string `json:"status"`
	SSOConfigured          bool   `json:"sso_configured"`
	ProvisioningConfigured bool   `json:"provisioning_configured"`
}

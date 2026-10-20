package collector

import (
	"context"
	"fmt"

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
func (c *Collector) processApp(app okta.Application, metrics *appMetricsCollector, level componentsdk.Level) {
	metrics.totalApps++

	sso := isSSO(app.SignOnMode)
	if sso {
		metrics.ssoApps++
	}

	hasProvisioning, hasDeprovisioning := checkProvisioningFeatures(app.Features)
	if hasProvisioning {
		metrics.provisioningEnabled++
	}
	if hasDeprovisioning {
		metrics.deprovisioningEnabled++
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		metrics.inventory = append(metrics.inventory, App{
			Label:                  app.Label,
			Name:                   app.Name,
			Type:                   appType(app.SignOnMode),
			SignOnMode:             app.SignOnMode,
			Status:                 app.Status,
			SSOConfigured:          sso,
			ProvisioningConfigured: hasProvisioning,
		})
	}
}

// appType maps an Okta sign-on mode to a coarse app type (SAML / OIDC / SWA / BOOKMARK).
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
// null when the app list could not be read or the org has no apps.
//
// Audit adds the per-app inventory.
type AppMetrics struct {
	TotalCount                 *int `json:"total_count"`                  // Apps; the population of the app percentages
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
	Type                   string `json:"type"` // SAML / OIDC / SWA / BOOKMARK
	SignOnMode             string `json:"sign_on_mode"`
	Status                 string `json:"status"`
	SSOConfigured          bool   `json:"sso_configured"`
	ProvisioningConfigured bool   `json:"provisioning_configured"`
}

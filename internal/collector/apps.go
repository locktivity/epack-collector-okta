package collector

import (
	"context"
	"fmt"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// appMetricsCollector holds intermediate app collection state.
type appMetricsCollector struct {
	totalApps             int
	ssoApps               int
	provisioningEnabled   int
	deprovisioningEnabled int
	ssoCoverage           int
	inventory             []App // Audit-level per-app rows
	inventoryTruncated    bool
	inventoryDropped      int
}

// toAppMetrics maps the collected app state onto the output DTO.
func (m *appMetricsCollector) toAppMetrics() AppMetrics {
	return AppMetrics{
		ProvisioningEnabled:   m.provisioningEnabled,
		DeprovisioningEnabled: m.deprovisioningEnabled,
		Inventory:             m.inventory,
		InventoryTruncated:    m.inventoryTruncated,
		InventoryDropped:      m.inventoryDropped,
	}
}

func (c *Collector) collectAppMetrics(ctx context.Context, level componentsdk.Level) (*appMetricsCollector, error) {
	metrics := &appMetricsCollector{}

	appCount := 0
	err := c.client.FetchApplications(ctx, func(apps []okta.Application) error {
		for _, app := range apps {
			c.processApp(app, metrics, level)
		}
		appCount += len(apps)
		c.status(fmt.Sprintf("Found %d applications...", appCount))
		return nil
	})

	if err != nil {
		c.warnSurface("applications", "okta.apps.read", err)
		return metrics, nil
	}

	metrics.ssoCoverage = percent(metrics.ssoApps, metrics.totalApps)
	metrics.provisioningEnabled = percent(metrics.provisioningEnabled, metrics.totalApps)
	metrics.deprovisioningEnabled = percent(metrics.deprovisioningEnabled, metrics.totalApps)

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

	return metrics, nil
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

// AppMetrics contains application lifecycle percentages (all 0-100).
//
// Audit adds the per-app inventory.
type AppMetrics struct {
	ProvisioningEnabled   int `json:"provisioning_enabled"`   // % apps with auto-provisioning
	DeprovisioningEnabled int `json:"deprovisioning_enabled"` // % apps with auto-deprovisioning

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

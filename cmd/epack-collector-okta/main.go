// epack-collector-okta collects Okta organization security posture.
//
// This binary is designed to be executed by the epack collector runner.
// It uses the epack Component SDK for protocol compliance.
package main

import (
	"github.com/locktivity/epack-collector-okta/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

// Version is set at build time via -ldflags
var Version = "dev"

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "okta",
		Version:     Version,
		Description: "Collects Okta organization security posture metrics",
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	// Build config from SDK context
	cfg := ctx.Config()
	config := collector.Config{
		OrgDomain:  getString(cfg, "org_domain"),
		ClientID:   getString(cfg, "client_id"),
		PrivateKey: ctx.Secret("OKTA_PRIVATE_KEY"),
		APIToken:   ctx.Secret("OKTA_API_TOKEN"),
	}

	if config.OrgDomain == "" {
		return componentsdk.NewConfigError("org_domain is required")
	}

	// Check for valid auth configuration
	hasOAuthAuth := config.ClientID != "" && config.PrivateKey != ""
	hasTokenAuth := config.APIToken != ""
	if !hasOAuthAuth && !hasTokenAuth {
		return componentsdk.NewConfigError("authentication required: provide client_id + OKTA_PRIVATE_KEY or OKTA_API_TOKEN")
	}

	// Create collector and collect posture
	c, err := collector.New(config)
	if err != nil {
		return componentsdk.NewConfigError("creating collector: %v", err)
	}
	posture, err := c.Collect(ctx.Context())
	if err != nil {
		return componentsdk.NewNetworkError("collecting posture: %v", err)
	}

	// Emit the collected data (SDK handles protocol envelope)
	return ctx.Emit(posture)
}

// getString safely extracts a string from config map
func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

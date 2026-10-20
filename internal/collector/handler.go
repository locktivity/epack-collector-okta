package collector

import (
	"time"

	"github.com/locktivity/epack-collector-okta/docs/schema"
	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        "okta",
		Version:     version,
		Commit:      commit,
		Description: "Collects Okta organization security posture metrics",
		// Large orgs at internal take minutes; a runner's EPACK_DEADLINE
		// shortens this.
		Timeout:  30 * time.Minute,
		Schemas:  schema.Schemas(),
		TraceMap: schema.TraceMap,
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in, and otherwise emits what it collected with a gap recorded
// for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	config := Config{
		OrgDomain:  getString(cfg, "org_domain"),
		ClientID:   getString(cfg, "client_id"),
		KeyID:      getString(cfg, "key_id"),
		PrivateKey: ctx.Secret("OKTA_PRIVATE_KEY"),
		APIToken:   ctx.Secret("OKTA_API_TOKEN"),
		OnStatus:   ctx.Status,
		OnProgress: ctx.Progress,
		Recorder:   componentsdk.Records(ctx),
		Now:        func() time.Time { return componentsdk.Now(ctx) },
	}
	if err := config.Validate(); err != nil {
		return err
	}
	config.HTTPClient = componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts: []string{okta.Host(config.OrgDomain)},
		VendorCode:      okta.VendorCode,
	})

	// The level selects both the OAuth scope set requested at token exchange
	// and the depth of collection.
	level := ctx.Level()
	c, err := New(config, level)
	if err != nil {
		return err
	}
	posture, err := c.Collect(ctx.Context(), level)
	if err != nil {
		return err
	}
	return ctx.Emit(c.Artifacts(posture))
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

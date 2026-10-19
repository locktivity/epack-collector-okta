package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// Collector collects Okta organization security posture.
type Collector struct {
	client   okta.OktaClient
	config   Config
	gaps     *gapLog
	warnings []string // Surface-level warnings accumulated during collection
}

// warn records a surface-level warning for diagnostics. Use it when a surface is
// skipped (missing scope, feature not licensed, transient error) so the customer
// can see what to grant without the whole run failing.
func (c *Collector) warn(format string, args ...interface{}) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}

// warnSurface records a standardized diagnostic for a surface that was skipped
// because of an API error, naming the scope to grant on a 403 so the customer
// can act on it. A skipped surface degrades the run; it never fails it.
func (c *Collector) warnSurface(surface, scope string, err error) {
	if okta.StatusCodeOf(err) == 403 {
		c.warn("%s: access denied (403; grant %s and an admin role that can read it)", surface, scope)
		return
	}
	c.warn("%s: %v", surface, err)
}

// status reports an indeterminate status update.
func (c *Collector) status(message string) {
	if c.config.OnStatus != nil {
		c.config.OnStatus(message)
	}
}

// progress reports a determinate progress update.
func (c *Collector) progress(current, total int64, message string) {
	if c.config.OnProgress != nil {
		c.config.OnProgress(current, total, message)
	}
}

// baseOAuthScopes are the scopes trust-level collection requests. Requesting the
// least-privilege set for the level keeps the issued token scoped to what the
// run actually needs.
var baseOAuthScopes = []string{
	"okta.users.read",
	"okta.groups.read",
	"okta.apps.read",
	"okta.policies.read",
	"okta.roles.read",
	"okta.deviceAssurance.read",
}

// auditOAuthScopes are the additional scopes audit / internal collection needs.
// Every audit-and-above surface (per-factor-type counts, groups, network zones,
// identity providers, API tokens, hooks, system log, org settings) requests its
// scope here, so a trust run stays least privilege. A scope the service app has
// not been granted is dropped from the issued token; the surfaces that need it
// are then left out with a gap rather than failing the run.
var auditOAuthScopes = []string{
	"okta.authenticators.read",
	"okta.networkZones.read",
	"okta.idps.read",
	"okta.eventHooks.read",
	"okta.inlineHooks.read",
	"okta.logs.read",
	"okta.orgs.read",
	"okta.apiTokens.read",
}

// scopesForLevel returns the OAuth scopes to request for a collection level.
func scopesForLevel(level componentsdk.Level) []string {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return baseOAuthScopes
	}
	scopes := make([]string, 0, len(baseOAuthScopes)+len(auditOAuthScopes))
	scopes = append(scopes, baseOAuthScopes...)
	scopes = append(scopes, auditOAuthScopes...)
	return scopes
}

// New creates a new Collector with the given configuration for collection at the
// given level. The level selects the OAuth scope set requested at token
// exchange (trust requests today's scopes; audit / internal additionally request
// the new read scopes).
// It supports two authentication methods:
//   - OAuth 2.0 (recommended): Set ClientID, KeyID, and PrivateKey
//   - API Token (legacy): Set APIToken
func New(config Config, level componentsdk.Level) (*Collector, error) {
	var client okta.OktaClient
	switch {
	case config.usesOAuth():
		if config.KeyID == "" {
			return nil, componentsdk.NewConfigError("key_id is required for OAuth 2.0 authentication")
		}
		oauthClient, err := okta.NewClientWithOAuth(config.HTTPClient, config.OrgDomain, config.ClientID, config.KeyID, []byte(config.PrivateKey), scopesForLevel(level), config.now)
		if err != nil {
			return nil, err
		}
		client = oauthClient
	case config.APIToken != "":
		client = okta.NewClient(config.HTTPClient, config.OrgDomain, config.APIToken)
	default:
		return nil, componentsdk.NewConfigError("authentication required: provide client_id + private_key (recommended) or api_token")
	}

	return NewWithClient(config, client), nil
}

// NewWithClient creates a Collector with a custom client (for testing).
func NewWithClient(config Config, client okta.OktaClient) *Collector {
	return &Collector{
		client: client,
		config: config,
		gaps:   newGapLog(config.Recorder),
	}
}

// Collect fetches and aggregates security posture metrics for the organization.
// level controls the depth of collection (trust / audit / internal). Unknown or
// empty levels are treated as LevelTrust by the SDK reader; callers should not
// pre-validate. See the README for per-surface field availability per level.
//
// Collect returns an error only when the sign-in fails. Any value it cannot
// read after that is left out of the artifact and recorded as a gap.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*OrgPosture, error) {
	if c.config.OrgDomain == "" {
		return nil, fmt.Errorf("org_domain is required")
	}

	// Reset surface-level warnings and gaps from any previous run.
	c.warnings = nil
	c.gaps = newGapLog(c.config.Recorder)

	c.status(fmt.Sprintf("Connecting to Okta org %s...", c.config.OrgDomain))
	if err := c.signIn(ctx); err != nil {
		return nil, err
	}

	posture := NewOrgPosture(c.config.OrgDomain, c.config.now())
	posture.CollectedAtLevel = string(level)

	c.status("Collecting user metrics...")
	userMetrics := c.collectUserMetrics(ctx, level)

	c.status("Collecting application metrics...")
	appMetrics := c.collectAppMetrics(ctx, level)

	c.status("Collecting privileged access metrics...")
	privilegedMetrics := c.collectPrivilegedMetrics(ctx, userMetrics, level)
	posture.PrivilegedAccess.CustomRoles = c.collectCustomRoles(ctx, level)

	c.status("Collecting policy metrics...")
	policyMetrics := c.collectPolicyMetrics(ctx, userMetrics, level)

	c.status("Collecting device access metrics...")
	deviceAccessMetrics := c.collectDeviceAccessMetrics(ctx, userMetrics, privilegedMetrics, policyMetrics)

	c.fillUsers(posture, userMetrics, level)
	c.fillApps(posture, appMetrics, level)
	c.fillPrivileged(posture, privilegedMetrics, level)
	c.fillPolicy(posture, userMetrics, policyMetrics, level)
	c.fillDeviceAccess(posture, userMetrics, privilegedMetrics, policyMetrics, deviceAccessMetrics, level)
	posture.Posture.PerFactorType = c.collectAuthenticatorMetrics(ctx, userMetrics, level)

	posture.Groups = c.collectGroups(ctx, level)
	posture.NetworkZones = c.collectNetworkZones(ctx, level)
	posture.IdentityProviders = c.collectIdentityProviders(ctx, level)
	posture.APITokens = c.collectAPITokens(ctx, level, userMetrics)
	posture.Hooks = c.collectHooks(ctx, level)
	posture.SystemLog = c.collectSystemLog(ctx, level)
	posture.OrgSettings = c.collectOrgSettings(ctx, level, userMetrics)

	if len(c.warnings) > 0 {
		posture.Diagnostics = &Diagnostics{Warnings: c.warnings}
	}

	c.status("Collection complete")

	return posture, nil
}

// signIn proves the credential works before any surface is read. It is the
// only call whose failure fails the run.
func (c *Collector) signIn(ctx context.Context) error {
	identity, err := c.client.SignIn(ctx)
	if err != nil {
		return fmt.Errorf("signing in to Okta: %w", err)
	}
	c.gaps.rec.SignedInAs(componentsdk.Principal{
		Provider: "okta",
		Kind:     identity.Kind,
		TenantID: okta.Host(c.config.OrgDomain),
		Scopes:   identity.Scopes,
		ID:       identity.ID,
	})
	return nil
}

// Artifacts returns the detailed artifact and, when it holds any evidence,
// the normalized identity-provider posture, whose values carry the gaps of
// the detailed values they copy.
func (c *Collector) Artifacts(posture *OrgPosture) []componentsdk.CollectedArtifact {
	artifacts := []componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(detailedPath, posture, componentsdk.ArtifactMeta{}),
	}
	normalized := posture.ToIDPPosture()
	if normalized == nil {
		return artifacts
	}
	c.mirrorIDPPostureGaps()
	return append(artifacts, componentsdk.JSONArtifact(idpPosturePath, normalized,
		componentsdk.ArtifactMeta{Schema: "evidencepack/idp-posture@v1"}))
}

// formatTime renders t as an RFC3339 UTC string, or "" if t is the zero value.
// Callers store the result in omitempty fields, so an unset timestamp is omitted
// rather than emitted as the zero date.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// percent returns count as a whole percentage of total, or nil when total is
// 0, since a percentage of nothing has no value.
func percent(count, total int) *int {
	if total == 0 {
		return nil
	}
	p := (count * MaxPercentage) / total
	return &p
}

func intPtr(i int) *int { return &i }

func boolPtr(b bool) *bool { return &b }

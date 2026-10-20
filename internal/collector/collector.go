package collector

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// Collector collects Okta organization security posture.
type Collector struct {
	client   okta.OktaClient
	config   Config
	gaps     *gapLog
	warnings []string       // Surface-level warnings accumulated during collection
	signedIn *okta.Identity // Who the sign-in proved the collector is
}

// warn records a surface-level warning for diagnostics and returns it. Use it
// when a surface is skipped (missing scope, feature not licensed, transient
// error) so the customer can see what to grant without the whole run failing.
func (c *Collector) warn(format string, args ...interface{}) string {
	message := fmt.Sprintf(format, args...)
	c.warnings = append(c.warnings, message)
	return message
}

// warnSurface records a standardized diagnostic for a surface, or one item's
// part of it, that was skipped because of an API error, and returns err with
// the diagnostic for the gaps it leaves. A skipped surface degrades the run;
// it never fails it.
func (c *Collector) warnSurface(surface, scope string, err error) error {
	return c.warnSurfaceRole(surface, scope, "an admin role that can read it", err)
}

// warnSurfaceRole is warnSurface for a surface that needs a particular admin
// role, which role names. A 403 says what to grant. The gaps it leaves name
// scope only when the service app asked for it and Okta did not grant it. A
// granted scope leaves the refusal to the service app's admin role, and an
// API token, which has no scopes, acts with its owner's admin roles.
func (c *Collector) warnSurfaceRole(surface, scope, role string, err error) error {
	if okta.StatusCodeOf(err) != http.StatusForbidden {
		return failed(err, c.warn("%s: %v", surface, err), "")
	}
	id := c.signedIn
	switch {
	case id != nil && id.AuthMethod == componentsdk.AuthAPIToken:
		return failed(err, c.warn("%s: access denied (403; the API token's owner needs %s)", surface, role), "")
	case id != nil && slices.Contains(id.Scopes, scope):
		return failed(err, c.warn("%s: access denied (403; %s is granted, so the service app needs %s)", surface, scope, role), "")
	}
	var missing string
	if id != nil && slices.Contains(id.RequestedScopes, scope) {
		missing = scope
	}
	return failed(err, c.warn("%s: access denied (403; grant %s and %s)", surface, scope, role), missing)
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

// stepper runs the parts of a collection one after another as the run's
// steps, each ending when the next one starts.
type stepper struct {
	ctx     context.Context
	current *componentsdk.Step
}

// next ends the current step and starts the one named name, returning the
// context the step's calls are made with.
func (s *stepper) next(name, title string) context.Context {
	s.end()
	ctx, step := componentsdk.StartStep(s.ctx, name, title)
	s.current = step
	return ctx
}

// end ends the current step, if there is one.
func (s *stepper) end() {
	s.current.End()
	s.current = nil
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

	// Each part of the collection is a step in the run's record. The last
	// eight read surfaces that only audit and internal collect.
	steps := &stepper{ctx: ctx}
	defer steps.end()

	c.status(fmt.Sprintf("Connecting to Okta org %s...", c.config.OrgDomain))
	if err := c.signIn(steps.next("sign_in", "Sign in")); err != nil {
		return nil, err
	}

	posture := NewOrgPosture(c.config.OrgDomain, c.config.now())
	posture.CollectedAtLevel = string(level)

	userMetrics := c.collectUserMetrics(steps.next("people", "People and sign-in methods"), level)
	appMetrics := c.collectAppMetrics(steps.next("apps", "Apps"), level)
	rolesCtx := steps.next("admin_roles", "Admin roles")
	privilegedMetrics := c.collectPrivilegedMetrics(rolesCtx, userMetrics, level)
	posture.PrivilegedAccess.CustomRoles = c.collectCustomRoles(rolesCtx, level)
	policyMetrics := c.collectPolicyMetrics(steps.next("policies", "Sign-on and MFA policies"), userMetrics, level)
	deviceAccessMetrics := c.collectDeviceAccessMetrics(steps.next("device_assurance", "Device assurance"), userMetrics, privilegedMetrics, policyMetrics)
	steps.end()

	c.fillUsers(posture, userMetrics, level)
	c.fillApps(posture, appMetrics, level)
	c.fillPrivileged(posture, privilegedMetrics, level)
	c.fillPolicy(posture, userMetrics, policyMetrics, level)
	c.fillDeviceAccess(posture, userMetrics, privilegedMetrics, policyMetrics, deviceAccessMetrics, level)

	if level.AtLeast(componentsdk.LevelAudit) {
		posture.Posture.PerFactorType = c.collectAuthenticatorMetrics(steps.next("authenticators", "Authenticators"), userMetrics, level)
		posture.Groups = c.collectGroups(steps.next("groups", "Groups"), level)
		posture.NetworkZones = c.collectNetworkZones(steps.next("network_zones", "Network zones"), level)
		posture.IdentityProviders = c.collectIdentityProviders(steps.next("identity_providers", "Identity providers"), level)
		posture.APITokens = c.collectAPITokens(steps.next("api_tokens", "API tokens"), level, userMetrics)
		posture.Hooks = c.collectHooks(steps.next("hooks", "Event and inline hooks"), level)
		posture.SystemLog = c.collectSystemLog(steps.next("system_log", "Activity log"), level)
		posture.OrgSettings = c.collectOrgSettings(steps.next("org_settings", "Org settings"), level, userMetrics)
		steps.end()
	}

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
	c.signedIn = identity
	c.gaps.rec.SignedInAs(componentsdk.Principal{
		Provider:        "okta",
		Kind:            identity.Kind,
		TenantID:        okta.Host(c.config.OrgDomain),
		AuthMethod:      identity.AuthMethod,
		RequestedScopes: identity.RequestedScopes,
		Scopes:          identity.Scopes,
		ReadOnly:        readOnly(identity),
		ID:              identity.ID,
	})
	return nil
}

// readOnly reports whether the sign-in's token can only read: a service
// app's token carries only scopes the collector asked for, and it asks only
// for read scopes. An API token acts with its owner's admin roles, which may
// change the org.
func readOnly(id *okta.Identity) bool {
	if id.AuthMethod != componentsdk.AuthPrivateKeyJWT {
		return false
	}
	for _, scope := range id.RequestedScopes {
		if !strings.HasSuffix(scope, ".read") {
			return false
		}
	}
	for _, scope := range id.Scopes {
		if !slices.Contains(id.RequestedScopes, scope) {
			return false
		}
	}
	return true
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

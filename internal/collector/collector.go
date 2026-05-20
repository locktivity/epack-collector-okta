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
// are then skipped with a diagnostic rather than failing the run.
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
//   - OAuth 2.0 (recommended): Set ClientID and PrivateKey
//   - API Token (legacy): Set APIToken
func New(config Config, level componentsdk.Level) (*Collector, error) {
	var client okta.OktaClient
	var err error

	if config.ClientID != "" && config.PrivateKey != "" {
		// OAuth 2.0 auth (recommended)
		if config.KeyID == "" {
			return nil, fmt.Errorf("key_id is required for OAuth 2.0 authentication")
		}
		client, err = okta.NewClientWithOAuth(
			config.OrgDomain,
			config.ClientID,
			config.KeyID,
			[]byte(config.PrivateKey),
			scopesForLevel(level),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth client: %w", err)
		}
	} else if config.APIToken != "" {
		// API token auth (legacy)
		client = okta.NewClient(config.OrgDomain, config.APIToken)
	} else {
		return nil, fmt.Errorf("authentication required: provide client_id + private_key (recommended) or api_token")
	}

	return &Collector{
		client: client,
		config: config,
	}, nil
}

// NewWithClient creates a Collector with a custom client (for testing).
func NewWithClient(config Config, client okta.OktaClient) *Collector {
	return &Collector{
		client: client,
		config: config,
	}
}

// Collect fetches and aggregates security posture metrics for the organization.
// level controls the depth of collection (trust / audit / internal). Unknown or
// empty levels are treated as LevelTrust by the SDK reader; callers should not
// pre-validate. See the README for per-surface field availability per level.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*OrgPosture, error) {
	if c.config.OrgDomain == "" {
		return nil, fmt.Errorf("org_domain is required")
	}

	// Reset surface-level warnings from any previous run.
	c.warnings = nil

	c.status(fmt.Sprintf("Connecting to Okta org %s...", c.config.OrgDomain))

	posture := NewOrgPosture(c.config.OrgDomain)
	posture.CollectedAtLevel = string(level)

	c.status("Collecting user metrics...")
	userMetrics, err := c.collectUserMetrics(ctx, level)
	if err != nil {
		return nil, fmt.Errorf("failed to collect user metrics: %w", err)
	}

	c.status("Collecting application metrics...")
	appMetrics, err := c.collectAppMetrics(ctx, level)
	if err != nil {
		return nil, fmt.Errorf("failed to collect app metrics: %w", err)
	}

	c.status("Collecting privileged access metrics...")
	privilegedMetrics, err := c.collectPrivilegedMetrics(ctx, userMetrics, level)
	if err != nil {
		return nil, fmt.Errorf("failed to collect privileged access metrics: %w", err)
	}

	c.status("Collecting policy metrics...")
	policyMetrics, err := c.collectPolicyMetrics(ctx, userMetrics, level)
	if err != nil {
		return nil, fmt.Errorf("failed to collect policy metrics: %w", err)
	}

	c.status("Collecting device access metrics...")
	deviceAccessMetrics, err := c.collectDeviceAccessMetrics(
		ctx,
		userMetrics,
		privilegedMetrics.privilegedUserIDs,
		policyMetrics.signOnPolicies,
		policyMetrics.groupMembers,
		level,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to collect device access metrics: %w", err)
	}

	posture.Posture = Posture{
		MFACoverage:          userMetrics.mfaEnrolled,
		MFAPhishingResistant: userMetrics.mfaPhishingResistant,
		SSOCoverage:          appMetrics.ssoCoverage,
		PerFactorType:        c.collectAuthenticatorMetrics(ctx, userMetrics, level),
	}
	if level.AtLeast(componentsdk.LevelAudit) {
		mfaDisabled := userMetrics.totalUsers - userMetrics.mfaEnrolledCount
		posture.Posture.MFADisabledUsersCount = &mfaDisabled
	}

	posture.Users = userMetrics.toUserMetrics()
	posture.Apps = appMetrics.toAppMetrics()
	posture.PrivilegedAccess = privilegedMetrics.toPrivilegedAccess()
	posture.Policy = policyMetrics.toPolicyConfig()
	posture.DeviceAccess = deviceAccessMetrics.toDeviceAccess()

	posture.Groups = c.collectGroups(ctx, level)
	posture.NetworkZones = c.collectNetworkZones(ctx, level)
	posture.IdentityProviders = c.collectIdentityProviders(ctx, level)

	loginByID := make(map[string]string, len(userMetrics.userByID))
	for id, u := range userMetrics.userByID {
		loginByID[id] = u.Profile.Login
	}
	posture.APITokens = c.collectAPITokens(ctx, level, loginByID)
	posture.Hooks = c.collectHooks(ctx, level)
	posture.SystemLog = c.collectSystemLog(ctx, level)
	posture.OrgSettings = c.collectOrgSettings(ctx, level)

	// Strict-superset normalization: at audit+, every level-gated array is
	// non-nil so consumers can rely on [] vs null to distinguish "none found"
	// from "not collected at this level" without reading collected_at_level.
	normalizeForLevel(posture, level)

	if len(c.warnings) > 0 {
		posture.Diagnostics = &Diagnostics{Warnings: c.warnings}
	}

	c.status("Collection complete")

	return posture, nil
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

// percent calculates the percentage of count over total, returning 0 if total is 0.
func percent(count, total int) int {
	if total == 0 {
		return 0
	}
	return (count * MaxPercentage) / total
}

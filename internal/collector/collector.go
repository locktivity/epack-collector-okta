package collector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
)

// Collector collects Okta organization security posture.
type Collector struct {
	client okta.OktaClient
	config Config
}

// New creates a new Collector with the given configuration.
// It supports two authentication methods:
//   - OAuth 2.0 (recommended): Set ClientID and PrivateKey
//   - API Token (legacy): Set APIToken
func New(config Config) (*Collector, error) {
	var client okta.OktaClient
	var err error

	if config.ClientID != "" && config.PrivateKey != "" {
		// OAuth 2.0 auth (recommended)
		client, err = okta.NewClientWithOAuth(
			config.OrgDomain,
			config.ClientID,
			[]byte(config.PrivateKey),
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
func (c *Collector) Collect(ctx context.Context) (*OrgPosture, error) {
	if c.config.OrgDomain == "" {
		return nil, fmt.Errorf("org_domain is required")
	}

	posture := NewOrgPosture(c.config.OrgDomain)

	userMetrics, err := c.collectUserMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect user metrics: %w", err)
	}

	appMetrics, err := c.collectAppMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect app metrics: %w", err)
	}

	policyMetrics, err := c.collectPolicyMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect policy metrics: %w", err)
	}

	posture.Posture = Posture{
		MFACoverage:          userMetrics.mfaEnrolled,
		MFAPhishingResistant: userMetrics.mfaPhishingResistant,
		SSOCoverage:          appMetrics.ssoCoverage,
	}

	posture.Users = UserMetrics{
		PasswordExpired: userMetrics.passwordExpired,
		LockedOut:       userMetrics.lockedOut,
		Inactive:        userMetrics.inactive,
	}

	posture.Apps = AppMetrics{
		ProvisioningEnabled:   appMetrics.provisioningEnabled,
		DeprovisioningEnabled: appMetrics.deprovisioningEnabled,
	}

	posture.Policy = PolicyConfig{
		PolicyCount:               policyMetrics.policyCount,
		MFARequiredAll:            policyMetrics.policyCount > 0 && policyMetrics.mfaRequiredCount >= policyMetrics.policyCount,
		MFARequiredAny:            policyMetrics.mfaRequiredCount > 0,
		SessionLifetimeMinMinutes: policyMetrics.sessionLifetimeMin,
		SessionLifetimeMaxMinutes: policyMetrics.sessionLifetimeMax,
		IdleTimeoutMinMinutes:     policyMetrics.idleTimeoutMin,
		IdleTimeoutMaxMinutes:     policyMetrics.idleTimeoutMax,
	}

	return posture, nil
}

// userMetricsCollector holds intermediate user collection state.
type userMetricsCollector struct {
	totalUsers           int
	mfaEnrolledCount     int
	mfaPhishingResistant int
	passwordExpired      int
	lockedOut            int
	inactive             int
	mfaEnrolled          int
}

func (c *Collector) collectUserMetrics(ctx context.Context) (*userMetricsCollector, error) {
	metrics := &userMetricsCollector{}
	inactiveThreshold := time.Now().AddDate(0, 0, -InactiveDaysThreshold)

	err := c.client.FetchUsers(ctx, func(users []okta.User) error {
		for _, user := range users {
			c.processUser(ctx, user, inactiveThreshold, metrics)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	metrics.mfaEnrolled = percent(metrics.mfaEnrolledCount, metrics.totalUsers)
	metrics.mfaPhishingResistant = percent(metrics.mfaPhishingResistant, metrics.totalUsers)
	metrics.passwordExpired = percent(metrics.passwordExpired, metrics.totalUsers)
	metrics.lockedOut = percent(metrics.lockedOut, metrics.totalUsers)
	metrics.inactive = percent(metrics.inactive, metrics.totalUsers)

	return metrics, nil
}

// processUser processes a single user and updates metrics.
func (c *Collector) processUser(ctx context.Context, user okta.User, inactiveThreshold time.Time, metrics *userMetricsCollector) {
	if user.Status == StatusDeprovisioned {
		return
	}

	metrics.totalUsers++

	if user.LastLogin.IsZero() || user.LastLogin.Before(inactiveThreshold) {
		metrics.inactive++
	}

	switch user.Status {
	case StatusPasswordExpired:
		metrics.passwordExpired++
	case StatusLockedOut:
		metrics.lockedOut++
	}

	c.processUserFactors(ctx, user.ID, metrics)
}

// processUserFactors checks MFA factors for a user.
func (c *Collector) processUserFactors(ctx context.Context, userID string, metrics *userMetricsCollector) {
	factors, err := c.client.FetchUserFactors(ctx, userID)
	if err != nil {
		return
	}

	hasMFA := false
	hasPhishingResistant := false

	for _, factor := range factors {
		if factor.Status != StatusActive {
			continue
		}

		hasMFA = true

		factorType := strings.ToLower(factor.FactorType)
		if factorType == FactorTypeWebAuthn || factorType == FactorTypeU2F {
			hasPhishingResistant = true
		}
	}

	if hasMFA {
		metrics.mfaEnrolledCount++
	}
	if hasPhishingResistant {
		metrics.mfaPhishingResistant++
	}
}

// appMetricsCollector holds intermediate app collection state.
type appMetricsCollector struct {
	totalApps             int
	ssoApps               int
	provisioningEnabled   int
	deprovisioningEnabled int
	ssoCoverage           int
}

func (c *Collector) collectAppMetrics(ctx context.Context) (*appMetricsCollector, error) {
	metrics := &appMetricsCollector{}

	err := c.client.FetchApplications(ctx, func(apps []okta.Application) error {
		for _, app := range apps {
			c.processApp(app, metrics)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	metrics.ssoCoverage = percent(metrics.ssoApps, metrics.totalApps)
	metrics.provisioningEnabled = percent(metrics.provisioningEnabled, metrics.totalApps)
	metrics.deprovisioningEnabled = percent(metrics.deprovisioningEnabled, metrics.totalApps)

	return metrics, nil
}

// processApp processes a single application and updates metrics.
func (c *Collector) processApp(app okta.Application, metrics *appMetricsCollector) {
	metrics.totalApps++

	if isSSO(app.SignOnMode) {
		metrics.ssoApps++
	}

	hasProvisioning, hasDeprovisioning := checkProvisioningFeatures(app.Features)
	if hasProvisioning {
		metrics.provisioningEnabled++
	}
	if hasDeprovisioning {
		metrics.deprovisioningEnabled++
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

// policyMetricsCollector holds intermediate policy collection state.
type policyMetricsCollector struct {
	policyCount        int
	mfaRequiredCount   int
	sessionLifetimeMin *int
	sessionLifetimeMax *int
	idleTimeoutMin     *int
	idleTimeoutMax     *int
}

func (c *Collector) collectPolicyMetrics(ctx context.Context) (*policyMetricsCollector, error) {
	metrics := &policyMetricsCollector{}

	c.collectSignOnPolicies(ctx, metrics)
	c.collectMFAEnrollPolicies(ctx, metrics)

	return metrics, nil
}

// collectSignOnPolicies collects sign-on policy metrics.
func (c *Collector) collectSignOnPolicies(ctx context.Context, metrics *policyMetricsCollector) {
	policies, err := c.client.FetchPolicies(ctx, PolicyTypeSignOn)
	if err != nil {
		return
	}

	for _, policy := range policies {
		if policy.Status != StatusActive {
			continue
		}

		rules, err := c.client.FetchPolicyRules(ctx, policy.ID)
		if err != nil {
			continue
		}

		if c.processSignOnRules(rules, metrics) {
			metrics.policyCount++
		}
	}
}

// processSignOnRules processes sign-on policy rules and returns true if policy has active rules.
func (c *Collector) processSignOnRules(rules []okta.PolicyRule, metrics *policyMetricsCollector) bool {
	for _, rule := range rules {
		if rule.Status != StatusActive || rule.Actions.Signon == nil {
			continue
		}

		signon := rule.Actions.Signon

		updateMinMax(&metrics.sessionLifetimeMin, &metrics.sessionLifetimeMax, signon.Session.MaxSessionLifetimeMinutes)
		updateMinMax(&metrics.idleTimeoutMin, &metrics.idleTimeoutMax, signon.Session.MaxSessionIdleMinutes)

		if signon.RequireFactor {
			metrics.mfaRequiredCount++
		}

		return true // Use first active rule per policy
	}
	return false
}

// collectMFAEnrollPolicies collects MFA enrollment policy metrics.
func (c *Collector) collectMFAEnrollPolicies(ctx context.Context, metrics *policyMetricsCollector) {
	policies, err := c.client.FetchPolicies(ctx, PolicyTypeMFAEnroll)
	if err != nil {
		return
	}

	for _, policy := range policies {
		if policy.Status != StatusActive {
			continue
		}

		rules, err := c.client.FetchPolicyRules(ctx, policy.ID)
		if err != nil {
			continue
		}

		c.processMFAEnrollRules(rules, metrics)
	}
}

// processMFAEnrollRules processes MFA enrollment policy rules.
func (c *Collector) processMFAEnrollRules(rules []okta.PolicyRule, metrics *policyMetricsCollector) {
	for _, rule := range rules {
		if rule.Status != StatusActive || rule.Actions.Enroll == nil {
			continue
		}

		enrollAction := strings.ToUpper(rule.Actions.Enroll.Self)
		if enrollAction == MFAActionChallenge || enrollAction == MFAActionLogin {
			metrics.mfaRequiredCount++
		}
		return // Use first active rule per policy
	}
}

// updateMinMax updates min/max pointers with a new value if applicable.
func updateMinMax(min, max **int, value int) {
	if value <= 0 {
		return
	}
	if *min == nil || value < **min {
		*min = &value
	}
	if *max == nil || value > **max {
		*max = &value
	}
}

// percent calculates the percentage of count over total, returning 0 if total is 0.
func percent(count, total int) int {
	if total == 0 {
		return 0
	}
	return (count * MaxPercentage) / total
}

package collector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
)

// Collector collects Okta organization security posture.
type Collector struct {
	client okta.OktaClient
	config Config
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

// New creates a new Collector with the given configuration.
// It supports two authentication methods:
//   - OAuth 2.0 (recommended): Set ClientID and PrivateKey
//   - API Token (legacy): Set APIToken
func New(config Config) (*Collector, error) {
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

	c.status(fmt.Sprintf("Connecting to Okta org %s...", c.config.OrgDomain))

	posture := NewOrgPosture(c.config.OrgDomain)

	c.status("Collecting user metrics...")
	userMetrics, err := c.collectUserMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect user metrics: %w", err)
	}

	c.status("Collecting application metrics...")
	appMetrics, err := c.collectAppMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect app metrics: %w", err)
	}

	c.status("Collecting privileged access metrics...")
	privilegedMetrics, err := c.collectPrivilegedMetrics(ctx, userMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to collect privileged access metrics: %w", err)
	}

	c.status("Collecting policy metrics...")
	policyMetrics, err := c.collectPolicyMetrics(ctx, userMetrics)
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
	)
	if err != nil {
		return nil, fmt.Errorf("failed to collect device access metrics: %w", err)
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
		Suspended:       userMetrics.suspended,
	}

	posture.Apps = AppMetrics{
		ProvisioningEnabled:   appMetrics.provisioningEnabled,
		DeprovisioningEnabled: appMetrics.deprovisioningEnabled,
	}

	posture.PrivilegedAccess = PrivilegedAccessMetrics{
		PrivilegedUsersCount:           privilegedMetrics.privilegedUsersCount,
		SuperAdminCount:                privilegedMetrics.superAdminCount,
		StandingPrivilegedUsersCount:   privilegedMetrics.standingPrivilegedUsersCount,
		PrivilegedMFACoveragePct:       privilegedMetrics.privilegedMFACoveragePct,
		PrivilegedPhishingResistantPct: privilegedMetrics.privilegedPhishingResistantPct,
	}

	posture.Policy = PolicyConfig{
		PolicyCount:               policyMetrics.policyCount,
		MFARequiredAll:            policyMetrics.mfaRequiredAll,
		MFARequiredAny:            policyMetrics.mfaRequiredAny,
		MFARequiredCoveragePct:    policyMetrics.mfaRequiredCoveragePct,
		SessionLifetimeMinMinutes: policyMetrics.sessionLifetimeMin,
		SessionLifetimeMaxMinutes: policyMetrics.sessionLifetimeMax,
		IdleTimeoutMinMinutes:     policyMetrics.idleTimeoutMin,
		IdleTimeoutMaxMinutes:     policyMetrics.idleTimeoutMax,
	}

	posture.DeviceAccess = DeviceAccessMetrics{
		ManagedDeviceRequired:            deviceAccessMetrics.managedDeviceRequired,
		ManagedDeviceRequiredCoveragePct: deviceAccessMetrics.managedDeviceRequiredCoveragePct,
		ManagedDeviceRequiredForAdmins:   deviceAccessMetrics.managedDeviceRequiredForAdmins,
		DeviceAssurancePoliciesCount:     deviceAccessMetrics.deviceAssurancePoliciesCount,
	}

	c.status("Collection complete")

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
	suspended            int
	mfaEnrolled          int
	users                []okta.User // Collected users for second pass
	userByID             map[string]okta.User
	hasMFAByUser         map[string]bool
	hasPhishingByUser    map[string]bool
}

func (c *Collector) collectUserMetrics(ctx context.Context) (*userMetricsCollector, error) {
	metrics := &userMetricsCollector{
		userByID:          make(map[string]okta.User),
		hasMFAByUser:      make(map[string]bool),
		hasPhishingByUser: make(map[string]bool),
	}
	inactiveThreshold := time.Now().AddDate(0, 0, -InactiveDaysThreshold)

	// First pass: fetch all users
	userCount := 0
	err := c.client.FetchUsers(ctx, func(users []okta.User) error {
		for _, user := range users {
			metrics.users = append(metrics.users, user)
			metrics.userByID[user.ID] = user
		}
		userCount += len(users)
		c.status(fmt.Sprintf("Found %d users...", userCount))
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Second pass: check MFA factors for each user
	total := int64(len(metrics.users))
	for i, user := range metrics.users {
		c.progress(int64(i+1), total, fmt.Sprintf("Checking MFA for user %d of %d", i+1, len(metrics.users)))
		c.processUser(ctx, user, inactiveThreshold, metrics)
	}

	metrics.mfaEnrolled = percent(metrics.mfaEnrolledCount, metrics.totalUsers)
	metrics.mfaPhishingResistant = percent(metrics.mfaPhishingResistant, metrics.totalUsers)
	metrics.passwordExpired = percent(metrics.passwordExpired, metrics.totalUsers)
	metrics.lockedOut = percent(metrics.lockedOut, metrics.totalUsers)
	metrics.inactive = percent(metrics.inactive, metrics.totalUsers)
	metrics.suspended = percent(metrics.suspended, metrics.totalUsers)

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
	case StatusSuspended:
		metrics.suspended++
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

	metrics.hasMFAByUser[userID] = hasMFA
	metrics.hasPhishingByUser[userID] = hasPhishingResistant
}

// appMetricsCollector holds intermediate app collection state.
type appMetricsCollector struct {
	totalApps             int
	ssoApps               int
	provisioningEnabled   int
	deprovisioningEnabled int
	ssoCoverage           int
}

// privilegedMetricsCollector holds privileged access counts and MFA coverage.
type privilegedMetricsCollector struct {
	privilegedUsersCount           int
	superAdminCount                int
	standingPrivilegedUsersCount   int
	privilegedMFAEnrolledCount     int
	privilegedPhishingFactorCount  int
	privilegedMFACoveragePct       int
	privilegedPhishingResistantPct int
	privilegedUserIDs              map[string]struct{} // Set of privileged user IDs for reuse
}

func (c *Collector) collectPrivilegedMetrics(ctx context.Context, userMetrics *userMetricsCollector) (*privilegedMetricsCollector, error) {
	metrics := &privilegedMetricsCollector{
		privilegedUserIDs: make(map[string]struct{}),
	}
	roleAssignedUserIDs := make(map[string]struct{})

	err := c.client.FetchUsersWithRoleAssignments(ctx, func(users []okta.RoleAssignedUser) error {
		for _, user := range users {
			roleAssignedUserIDs[user.ID] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	total := int64(len(roleAssignedUserIDs))
	current := int64(0)
	for userID := range roleAssignedUserIDs {
		current++
		c.progress(current, total, fmt.Sprintf("Checking privileged roles for user %d of %d", current, total))

		user, ok := userMetrics.userByID[userID]
		if !ok {
			return nil, fmt.Errorf("role-assigned user %s missing from user inventory", userID)
		}
		if user.Status == StatusDeprovisioned || user.Status == StatusSuspended {
			continue
		}

		roles, err := c.client.FetchUserRoleAssignments(ctx, userID)
		if err != nil {
			return nil, err
		}
		if len(roles) == 0 {
			continue
		}

		metrics.privilegedUsersCount++
		metrics.standingPrivilegedUsersCount++
		metrics.privilegedUserIDs[userID] = struct{}{}

		if userMetrics.hasMFAByUser[userID] {
			metrics.privilegedMFAEnrolledCount++
		}
		if userMetrics.hasPhishingByUser[userID] {
			metrics.privilegedPhishingFactorCount++
		}
		if hasRoleType(roles, RoleTypeSuperAdmin) {
			metrics.superAdminCount++
		}
	}

	metrics.privilegedMFACoveragePct = percent(metrics.privilegedMFAEnrolledCount, metrics.privilegedUsersCount)
	metrics.privilegedPhishingResistantPct = percent(metrics.privilegedPhishingFactorCount, metrics.privilegedUsersCount)

	return metrics, nil
}

func (c *Collector) collectAppMetrics(ctx context.Context) (*appMetricsCollector, error) {
	metrics := &appMetricsCollector{}

	appCount := 0
	err := c.client.FetchApplications(ctx, func(apps []okta.Application) error {
		for _, app := range apps {
			c.processApp(app, metrics)
		}
		appCount += len(apps)
		c.status(fmt.Sprintf("Found %d applications...", appCount))
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

func hasRoleType(roles []okta.RoleAssignment, roleType string) bool {
	for _, role := range roles {
		if strings.EqualFold(role.Type, roleType) {
			return true
		}
	}
	return false
}

// policyMetricsCollector holds intermediate policy collection state.
type policyMetricsCollector struct {
	policyCount            int
	totalUsers             int
	mfaRequiredUsers       int
	mfaRequiredAll         bool
	mfaRequiredAny         bool
	mfaRequiredCoveragePct int
	sessionLifetimeMin     *int
	sessionLifetimeMax     *int
	idleTimeoutMin         *int
	idleTimeoutMax         *int
	// Shared data for device access metrics
	signOnPolicies []scopedPolicy
	groupMembers   map[string]map[string]struct{}
}

type scopedPolicy struct {
	policy okta.Policy
	rules  []okta.PolicyRule
}

func (c *Collector) collectPolicyMetrics(ctx context.Context, userMetrics *userMetricsCollector) (*policyMetricsCollector, error) {
	metrics := &policyMetricsCollector{}

	c.status("Checking sign-on policies...")
	signOnPolicies, err := c.fetchActivePoliciesWithRules(ctx, PolicyTypeSignOn)
	if err != nil {
		return nil, err
	}
	metrics.policyCount = len(signOnPolicies)
	metrics.signOnPolicies = signOnPolicies
	metrics.updateSignOnTimeouts(signOnPolicies)

	c.status("Checking MFA enrollment policies...")
	mfaEnrollPolicies, err := c.fetchActivePoliciesWithRules(ctx, PolicyTypeMFAEnroll)
	if err != nil {
		return nil, err
	}

	allPolicies := make([]scopedPolicy, 0, len(signOnPolicies)+len(mfaEnrollPolicies))
	allPolicies = append(allPolicies, signOnPolicies...)
	allPolicies = append(allPolicies, mfaEnrollPolicies...)

	c.status("Resolving policy group memberships...")
	groupMembers, err := c.fetchGroupMembersForPolicies(ctx, allPolicies)
	if err != nil {
		return nil, err
	}
	metrics.groupMembers = groupMembers

	metrics.totalUsers = userMetrics.totalUsers
	total := int64(len(userMetrics.users))
	for i, user := range userMetrics.users {
		c.progress(int64(i+1), total, fmt.Sprintf("Evaluating MFA policy coverage for user %d of %d", i+1, len(userMetrics.users)))

		if user.Status == StatusDeprovisioned {
			continue
		}

		if userCoveredByMFARequirement(user.ID, signOnPolicies, mfaEnrollPolicies, groupMembers) {
			metrics.mfaRequiredUsers++
		}
	}

	metrics.mfaRequiredCoveragePct = percent(metrics.mfaRequiredUsers, metrics.totalUsers)
	metrics.mfaRequiredAny = metrics.mfaRequiredUsers > 0
	metrics.mfaRequiredAll = metrics.totalUsers > 0 && metrics.mfaRequiredUsers == metrics.totalUsers

	return metrics, nil
}

func (m *policyMetricsCollector) updateSignOnTimeouts(policies []scopedPolicy) {
	for _, scopedPolicy := range policies {
		for _, rule := range scopedPolicy.rules {
			if rule.Status != StatusActive || rule.Actions.Signon == nil {
				continue
			}

			signon := rule.Actions.Signon
			updateMinMax(&m.sessionLifetimeMin, &m.sessionLifetimeMax, signon.Session.MaxSessionLifetimeMinutes)
			updateMinMax(&m.idleTimeoutMin, &m.idleTimeoutMax, signon.Session.MaxSessionIdleMinutes)
		}
	}
}

func (c *Collector) fetchActivePoliciesWithRules(ctx context.Context, policyType string) ([]scopedPolicy, error) {
	policies, err := c.client.FetchPolicies(ctx, policyType)
	if err != nil {
		return nil, err
	}

	activePolicies := make([]okta.Policy, 0, len(policies))
	for _, policy := range policies {
		if policy.Status != StatusActive {
			continue
		}
		activePolicies = append(activePolicies, policy)
	}

	sort.Slice(activePolicies, func(i, j int) bool {
		return activePolicies[i].Priority < activePolicies[j].Priority
	})

	result := make([]scopedPolicy, 0, len(activePolicies))
	for _, policy := range activePolicies {
		rules, err := c.client.FetchPolicyRules(ctx, policy.ID)
		if err != nil {
			return nil, err
		}

		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Priority < rules[j].Priority
		})

		result = append(result, scopedPolicy{
			policy: policy,
			rules:  rules,
		})
	}

	return result, nil
}

func (c *Collector) fetchGroupMembersForPolicies(ctx context.Context, policies []scopedPolicy) (map[string]map[string]struct{}, error) {
	groupIDs := collectPolicyGroupIDs(policies)
	groupMembers := make(map[string]map[string]struct{}, len(groupIDs))
	if len(groupIDs) == 0 {
		return groupMembers, nil
	}

	total := int64(len(groupIDs))
	for i, groupID := range groupIDs {
		c.progress(int64(i+1), total, fmt.Sprintf("Loading policy group %d of %d", i+1, len(groupIDs)))

		members := make(map[string]struct{})
		if err := c.client.FetchGroupUsers(ctx, groupID, func(users []okta.User) error {
			for _, user := range users {
				members[user.ID] = struct{}{}
			}
			return nil
		}); err != nil {
			return nil, err
		}

		groupMembers[groupID] = members
	}

	return groupMembers, nil
}

func collectPolicyGroupIDs(policies []scopedPolicy) []string {
	groupIDs := make(map[string]struct{})

	for _, scopedPolicy := range policies {
		collectGroupIDsFromPeopleCondition(scopedPolicy.policy.Conditions.People, groupIDs)
		for _, rule := range scopedPolicy.rules {
			collectGroupIDsFromPeopleCondition(rule.Conditions.People, groupIDs)
		}
	}

	ids := make([]string, 0, len(groupIDs))
	for groupID := range groupIDs {
		ids = append(ids, groupID)
	}
	sort.Strings(ids)

	return ids
}

func collectGroupIDsFromPeopleCondition(people *okta.PolicyPeopleCondition, groupIDs map[string]struct{}) {
	if people == nil || people.Groups == nil {
		return
	}

	for _, groupID := range people.Groups.Include {
		groupIDs[groupID] = struct{}{}
	}
	for _, groupID := range people.Groups.Exclude {
		groupIDs[groupID] = struct{}{}
	}
}

func userCoveredByMFARequirement(
	userID string,
	signOnPolicies []scopedPolicy,
	mfaEnrollPolicies []scopedPolicy,
	groupMembers map[string]map[string]struct{},
) bool {
	return signOnPolicyRequiresMFA(userID, signOnPolicies, groupMembers) ||
		mfaEnrollmentPolicyRequiresMFA(userID, mfaEnrollPolicies, groupMembers)
}

func signOnPolicyRequiresMFA(userID string, policies []scopedPolicy, groupMembers map[string]map[string]struct{}) bool {
	for _, scopedPolicy := range policies {
		if !matchesPeopleCondition(userID, scopedPolicy.policy.Conditions.People, groupMembers) {
			continue
		}

		return firstMatchingSignOnRuleRequiresMFA(userID, scopedPolicy.rules, groupMembers)
	}

	return false
}

func firstMatchingSignOnRuleRequiresMFA(userID string, rules []okta.PolicyRule, groupMembers map[string]map[string]struct{}) bool {
	for _, rule := range rules {
		if rule.Status != StatusActive || rule.Actions.Signon == nil {
			continue
		}
		if !matchesPeopleCondition(userID, rule.Conditions.People, groupMembers) {
			continue
		}

		return rule.Actions.Signon.RequireFactor
	}

	return false
}

func mfaEnrollmentPolicyRequiresMFA(userID string, policies []scopedPolicy, groupMembers map[string]map[string]struct{}) bool {
	for _, scopedPolicy := range policies {
		if !matchesPeopleCondition(userID, scopedPolicy.policy.Conditions.People, groupMembers) {
			continue
		}

		return firstMatchingMFAEnrollRuleRequiresMFA(userID, scopedPolicy.rules, groupMembers)
	}

	return false
}

func firstMatchingMFAEnrollRuleRequiresMFA(userID string, rules []okta.PolicyRule, groupMembers map[string]map[string]struct{}) bool {
	for _, rule := range rules {
		if rule.Status != StatusActive || rule.Actions.Enroll == nil {
			continue
		}
		if !matchesPeopleCondition(userID, rule.Conditions.People, groupMembers) {
			continue
		}

		enrollAction := strings.ToUpper(rule.Actions.Enroll.Self)
		return enrollAction == MFAActionChallenge || enrollAction == MFAActionLogin
	}

	return false
}

func matchesPeopleCondition(userID string, people *okta.PolicyPeopleCondition, groupMembers map[string]map[string]struct{}) bool {
	if people == nil {
		return true
	}

	included := !hasPeopleIncludes(people)
	if people.Users != nil && containsString(people.Users.Include, userID) {
		included = true
	}
	if people.Groups != nil && userInAnyGroup(userID, people.Groups.Include, groupMembers) {
		included = true
	}
	if !included {
		return false
	}

	if people.Users != nil && containsString(people.Users.Exclude, userID) {
		return false
	}
	if people.Groups != nil && userInAnyGroup(userID, people.Groups.Exclude, groupMembers) {
		return false
	}

	return true
}

func hasPeopleIncludes(people *okta.PolicyPeopleCondition) bool {
	if people == nil {
		return false
	}

	return (people.Users != nil && len(people.Users.Include) > 0) ||
		(people.Groups != nil && len(people.Groups.Include) > 0)
}

func userInAnyGroup(userID string, groupIDs []string, groupMembers map[string]map[string]struct{}) bool {
	for _, groupID := range groupIDs {
		if members, ok := groupMembers[groupID]; ok {
			if _, ok := members[userID]; ok {
				return true
			}
		}
	}

	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

// deviceAccessMetricsCollector holds device access enforcement state.
type deviceAccessMetricsCollector struct {
	managedDeviceRequired            bool
	managedDeviceRequiredUsers       int
	managedDeviceRequiredAdmins      int
	deviceAssurancePoliciesCount     int
	managedDeviceRequiredCoveragePct int
	managedDeviceRequiredForAdmins   bool
}

func (c *Collector) collectDeviceAccessMetrics(
	ctx context.Context,
	userMetrics *userMetricsCollector,
	privilegedUserIDs map[string]struct{},
	signOnPolicies []scopedPolicy,
	groupMembers map[string]map[string]struct{},
) (*deviceAccessMetricsCollector, error) {
	metrics := &deviceAccessMetricsCollector{}

	// Fetch device assurance policies count
	c.status("Checking device assurance policies...")
	deviceAssurancePolicies, err := c.client.FetchDeviceAssurancePolicies(ctx)
	if err != nil {
		return nil, err
	}
	metrics.deviceAssurancePoliciesCount = len(deviceAssurancePolicies)

	// Check if any sign-on rule requires managed devices
	metrics.managedDeviceRequired = anySignOnRuleRequiresManagedDevice(signOnPolicies)

	// Evaluate per-user coverage
	c.status("Evaluating device access coverage...")
	totalUsers := 0
	totalAdmins := len(privilegedUserIDs)
	for _, user := range userMetrics.users {
		if user.Status == StatusDeprovisioned {
			continue
		}
		totalUsers++

		if userCoveredByManagedDeviceRequirement(user.ID, signOnPolicies, groupMembers) {
			metrics.managedDeviceRequiredUsers++

			if _, isAdmin := privilegedUserIDs[user.ID]; isAdmin {
				metrics.managedDeviceRequiredAdmins++
			}
		}
	}

	metrics.managedDeviceRequiredCoveragePct = percent(metrics.managedDeviceRequiredUsers, totalUsers)
	metrics.managedDeviceRequiredForAdmins = totalAdmins > 0 && metrics.managedDeviceRequiredAdmins == totalAdmins

	return metrics, nil
}

// anySignOnRuleRequiresManagedDevice checks if any active sign-on rule has a managed device requirement.
func anySignOnRuleRequiresManagedDevice(policies []scopedPolicy) bool {
	for _, sp := range policies {
		for _, rule := range sp.rules {
			if rule.Status != StatusActive {
				continue
			}
			if ruleRequiresManagedDevice(rule) {
				return true
			}
		}
	}
	return false
}

// userCoveredByManagedDeviceRequirement checks if a user is covered by a managed device requirement.
func userCoveredByManagedDeviceRequirement(
	userID string,
	signOnPolicies []scopedPolicy,
	groupMembers map[string]map[string]struct{},
) bool {
	for _, sp := range signOnPolicies {
		if !matchesPeopleCondition(userID, sp.policy.Conditions.People, groupMembers) {
			continue
		}

		if firstMatchingSignOnRuleRequiresManagedDevice(userID, sp.rules, groupMembers) {
			return true
		}
	}
	return false
}

// firstMatchingSignOnRuleRequiresManagedDevice checks if the first matching rule for a user requires managed device.
func firstMatchingSignOnRuleRequiresManagedDevice(
	userID string,
	rules []okta.PolicyRule,
	groupMembers map[string]map[string]struct{},
) bool {
	for _, rule := range rules {
		if rule.Status != StatusActive {
			continue
		}
		if !matchesPeopleCondition(userID, rule.Conditions.People, groupMembers) {
			continue
		}

		// First matching rule determines the result
		return ruleRequiresManagedDevice(rule)
	}
	return false
}

// ruleRequiresManagedDevice checks if a policy rule has a managed device condition.
func ruleRequiresManagedDevice(rule okta.PolicyRule) bool {
	if rule.Conditions.Device == nil {
		return false
	}
	return strings.EqualFold(rule.Conditions.Device.Managed, "true")
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

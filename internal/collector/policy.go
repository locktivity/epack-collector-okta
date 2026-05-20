package collector

import (
	"context"
	"fmt"
	"sort"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// policyMetricsCollector holds intermediate policy collection state.
type policyMetricsCollector struct {
	policyCount            int
	totalUsers             int
	mfaRequiredUsers       int
	mfaRequiredAll         bool
	mfaRequiredAny         bool
	mfaRequiredCoveragePct int
	sessionLifetime        minMax
	idleTimeout            minMax
	// Shared data for device access metrics
	signOnPolicies []scopedPolicy
	groupMembers   groupMembership
	// Audit-level per-policy summaries (sign-on + MFA-enroll policies).
	policies []PolicySummary
}

type scopedPolicy struct {
	policy okta.Policy
	rules  []okta.PolicyRule
}

// toPolicyConfig maps the collected policy state onto the output DTO.
func (m *policyMetricsCollector) toPolicyConfig() PolicyConfig {
	return PolicyConfig{
		PolicyCount:               m.policyCount,
		MFARequiredAll:            m.mfaRequiredAll,
		MFARequiredAny:            m.mfaRequiredAny,
		MFARequiredCoveragePct:    m.mfaRequiredCoveragePct,
		SessionLifetimeMinMinutes: m.sessionLifetime.min,
		SessionLifetimeMaxMinutes: m.sessionLifetime.max,
		IdleTimeoutMinMinutes:     m.idleTimeout.min,
		IdleTimeoutMaxMinutes:     m.idleTimeout.max,
		Policies:                  m.policies,
	}
}

func (c *Collector) collectPolicyMetrics(ctx context.Context, userMetrics *userMetricsCollector, level componentsdk.Level) (*policyMetricsCollector, error) {
	metrics := &policyMetricsCollector{}

	c.status("Checking sign-on policies...")
	signOnPolicies, err := c.fetchActivePoliciesWithRules(ctx, PolicyTypeSignOn)
	if err != nil {
		c.warnSurface("sign-on policies", "okta.policies.read", err)
		signOnPolicies = nil
	}
	metrics.policyCount = len(signOnPolicies)
	metrics.signOnPolicies = signOnPolicies
	metrics.updateSignOnTimeouts(signOnPolicies)

	c.status("Checking MFA enrollment policies...")
	mfaEnrollPolicies, err := c.fetchActivePoliciesWithRules(ctx, PolicyTypeMFAEnroll)
	if err != nil {
		c.warnSurface("MFA-enrollment policies", "okta.policies.read", err)
		mfaEnrollPolicies = nil
	}

	allPolicies := make([]scopedPolicy, 0, len(signOnPolicies)+len(mfaEnrollPolicies))
	allPolicies = append(allPolicies, signOnPolicies...)
	allPolicies = append(allPolicies, mfaEnrollPolicies...)

	if level.AtLeast(componentsdk.LevelAudit) {
		metrics.policies = make([]PolicySummary, 0, len(allPolicies))
		for _, sp := range allPolicies {
			metrics.policies = append(metrics.policies, policySummary(sp, level))
		}
	}

	c.status("Resolving policy group memberships...")
	groupMembers, err := c.fetchGroupMembersForPolicies(ctx, allPolicies)
	if err != nil {
		c.warnSurface("policy group memberships", "okta.groups.read", err)
		groupMembers = groupMembership{}
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
			m.sessionLifetime.observe(signon.Session.MaxSessionLifetimeMinutes)
			m.idleTimeout.observe(signon.Session.MaxSessionIdleMinutes)
		}
	}
}

// policySummary projects a scopedPolicy onto its audit-level summary row. At
// internal level it also attaches per-rule condition / action details.
func policySummary(sp scopedPolicy, level componentsdk.Level) PolicySummary {
	summary := PolicySummary{
		Name:         sp.policy.Name,
		Type:         sp.policy.Type,
		Status:       sp.policy.Status,
		Priority:     sp.policy.Priority,
		RuleCount:    len(sp.rules),
		ScopeSummary: policyScopeSummary(sp.policy.Conditions.People),
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		summary.Rules = make([]PolicyRuleDetail, 0, len(sp.rules))
		for _, rule := range sp.rules {
			summary.Rules = append(summary.Rules, policyRuleDetail(rule))
		}
	}
	return summary
}

// policyRuleDetail flattens a policy rule's conditions and actions for internal
// emission. Field names are collector-defined, not Okta-internal identifiers.
func policyRuleDetail(rule okta.PolicyRule) PolicyRuleDetail {
	detail := PolicyRuleDetail{
		Name:     rule.Name,
		Priority: rule.Priority,
		Status:   rule.Status,
	}

	if people := rule.Conditions.People; people != nil {
		if people.Groups != nil {
			detail.GroupsIncluded = append([]string(nil), people.Groups.Include...)
			detail.GroupsExcluded = append([]string(nil), people.Groups.Exclude...)
		}
	}
	if net := rule.Conditions.Network; net != nil {
		detail.NetworkConnection = net.Connection
		detail.NetworkZonesIncluded = append([]string(nil), net.Include...)
	}
	if rule.Conditions.Device != nil {
		detail.DeviceManaged = rule.Conditions.Device.Managed
	}

	if signon := rule.Actions.Signon; signon != nil {
		detail.Access = signon.Access
		requireFactor := signon.RequireFactor
		detail.RequireFactor = &requireFactor
		detail.FactorPromptMode = signon.FactorPromptMode
		if signon.Session.MaxSessionLifetimeMinutes > 0 {
			v := signon.Session.MaxSessionLifetimeMinutes
			detail.MaxSessionLifetimeMinutes = &v
		}
		if signon.Session.MaxSessionIdleMinutes > 0 {
			v := signon.Session.MaxSessionIdleMinutes
			detail.MaxSessionIdleMinutes = &v
		}
		persistent := signon.Session.UsePersistentCookie
		detail.PersistentCookie = &persistent
	}
	if enroll := rule.Actions.Enroll; enroll != nil {
		detail.EnrollSelf = enroll.Self
	}

	return detail
}

// policyScopeSummary describes whether a policy targets specific groups/users or
// applies to everyone.
func policyScopeSummary(people *okta.PolicyPeopleCondition) string {
	if hasPeopleIncludes(people) {
		return "group-assigned"
	}
	return "everyone"
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

func (c *Collector) fetchGroupMembersForPolicies(ctx context.Context, policies []scopedPolicy) (groupMembership, error) {
	groupIDs := collectPolicyGroupIDs(policies)
	groupMembers := make(groupMembership, len(groupIDs))
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

// minMax tracks the smallest and largest positive value observed, as nilable
// pointers so an unobserved accumulator emits null.
type minMax struct {
	min, max *int
}

// observe folds a value into the running min/max. Non-positive values are ignored
// (Okta reports 0 for "unset" session/idle limits).
func (mm *minMax) observe(value int) {
	if value <= 0 {
		return
	}
	if mm.min == nil || value < *mm.min {
		v := value
		mm.min = &v
	}
	if mm.max == nil || value > *mm.max {
		v := value
		mm.max = &v
	}
}

// PolicyConfig contains aggregated policy settings across all active policies.
type PolicyConfig struct {
	PolicyCount               int  `json:"policy_count"`                 // Number of active sign-on policies
	MFARequiredAll            bool `json:"mfa_required_all"`             // MFA is required for all non-deprovisioned users
	MFARequiredAny            bool `json:"mfa_required_any"`             // MFA is required for at least one non-deprovisioned user
	MFARequiredCoveragePct    int  `json:"mfa_required_coverage_pct"`    // % of non-deprovisioned users covered by an MFA requirement
	SessionLifetimeMinMinutes *int `json:"session_lifetime_min_minutes"` // Shortest session lifetime across active sign-on rules
	SessionLifetimeMaxMinutes *int `json:"session_lifetime_max_minutes"` // Longest session lifetime across active sign-on rules
	IdleTimeoutMinMinutes     *int `json:"idle_timeout_min_minutes"`     // Shortest idle timeout across active sign-on rules
	IdleTimeoutMaxMinutes     *int `json:"idle_timeout_max_minutes"`     // Longest idle timeout across active sign-on rules

	// Audit-level field.
	Policies []PolicySummary `json:"policies,omitempty"`
}

// PolicySummary is a per-policy summary (audit+). Internal adds per-rule details.
type PolicySummary struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Status       string `json:"status"`
	Priority     int    `json:"priority"`
	RuleCount    int    `json:"rule_count"`
	ScopeSummary string `json:"scope_summary"` // "group-assigned" or "everyone"

	// Internal-level field.
	Rules []PolicyRuleDetail `json:"rules,omitempty"`
}

// PolicyRuleDetail captures a policy rule's conditions and actions (internal).
type PolicyRuleDetail struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Status   string `json:"status"`

	// Conditions.
	NetworkConnection    string   `json:"network_connection,omitempty"`
	NetworkZonesIncluded []string `json:"network_zones_included,omitempty"`
	GroupsIncluded       []string `json:"groups_included,omitempty"`
	GroupsExcluded       []string `json:"groups_excluded,omitempty"`
	DeviceManaged        string   `json:"device_managed,omitempty"`

	// Sign-on actions.
	Access                    string `json:"access,omitempty"`
	RequireFactor             *bool  `json:"require_factor,omitempty"`
	FactorPromptMode          string `json:"factor_prompt_mode,omitempty"`
	MaxSessionLifetimeMinutes *int   `json:"max_session_lifetime_minutes,omitempty"`
	MaxSessionIdleMinutes     *int   `json:"max_session_idle_minutes,omitempty"`
	PersistentCookie          *bool  `json:"persistent_cookie,omitempty"`

	// MFA-enroll action.
	EnrollSelf string `json:"enroll_self,omitempty"`
}

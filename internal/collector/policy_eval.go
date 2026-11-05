package collector

import (
	"sort"
	"strings"

	"github.com/locktivity/epack-collector-okta/internal/okta"
)

// Policy evaluation: pure functions that decide, for a given user, whether the
// org's active policies require MFA or a managed device, plus the people-condition
// matching they share. No I/O.

// groupMembership maps a group ID to the set of its member user IDs. It is the
// resolved membership of the groups referenced by policy people-conditions.
type groupMembership map[string]map[string]struct{}

// userInAny reports whether the user belongs to any of the given groups.
func (gm groupMembership) userInAny(userID string, groupIDs []string) bool {
	for _, groupID := range groupIDs {
		if members, ok := gm[groupID]; ok {
			if _, ok := members[userID]; ok {
				return true
			}
		}
	}
	return false
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
	groupMembers groupMembership,
) bool {
	return signOnPolicyRequiresMFA(userID, signOnPolicies, groupMembers) ||
		mfaEnrollmentPolicyRequiresMFA(userID, mfaEnrollPolicies, groupMembers)
}

// signOnPolicyRequiresMFA, mfaEnrollmentPolicyRequiresMFA and
// userCoveredByManagedDeviceRequirement follow Okta's evaluation order.
// Policies that apply to the user are evaluated in priority order, and so are
// the rules of each policy. The first rule whose conditions are all met
// applies. When no rule of a policy applies, the next policy is evaluated.
func signOnPolicyRequiresMFA(userID string, policies []scopedPolicy, groupMembers groupMembership) bool {
	return firstMatchingRuleDecides(userID, policies, groupMembers, ruleHasSignonAction, signonRuleMFADecision)
}

func mfaEnrollmentPolicyRequiresMFA(userID string, policies []scopedPolicy, groupMembers groupMembership) bool {
	return firstMatchingRuleDecides(userID, policies, groupMembers, ruleHasEnrollAction, alwaysDecides(enrollRuleRequiresFactor))
}

// ruleDecision gives the result for a rule that matches the user. decided is
// false when the rule settles only some of the user's sign-ins, and the next
// matching rule settles the others.
type ruleDecision func(okta.PolicyRule) (covered, decided bool)

// alwaysDecides is the ruleDecision of a rule that settles every sign-in.
func alwaysDecides(predicate func(okta.PolicyRule) bool) ruleDecision {
	return func(r okta.PolicyRule) (bool, bool) { return predicate(r), true }
}

// firstMatchingRuleDecides walks the policies whose people condition matches
// the user, in order, and their active in-scope rules whose people condition
// matches the user. The first rule that decides gives the result. A policy
// with no such rule leaves the user to the next policy, and the result is
// false when no rule decides. inScope picks the rules that take part, such
// as only sign-on rules.
func firstMatchingRuleDecides(userID string, policies []scopedPolicy, groupMembers groupMembership, inScope func(okta.PolicyRule) bool, decide ruleDecision) bool {
	for _, sp := range policies {
		if !matchesPeopleCondition(userID, sp.policy.Conditions.People, groupMembers) {
			continue
		}
		for _, rule := range sp.rules {
			if rule.Status != StatusActive || !inScope(rule) {
				continue
			}
			if !matchesPeopleCondition(userID, rule.Conditions.People, groupMembers) {
				continue
			}
			if covered, decided := decide(rule); decided {
				return covered
			}
		}
	}
	return false
}

// Rule scope filters passed to firstMatchingRuleDecides.
func ruleHasSignonAction(r okta.PolicyRule) bool { return r.Actions.Signon != nil }
func ruleHasEnrollAction(r okta.PolicyRule) bool { return r.Actions.Enroll != nil }
func anyRule(okta.PolicyRule) bool               { return true }

// signonRuleMFADecision gives the MFA result for a sign-on rule that matches
// the user. A rule with a condition on how the person signs in, such as a
// network zone, applies to only some of their sign-ins. When those sign-ins
// get in without MFA, the user is not covered. When they must use MFA or are
// denied, the user's other sign-ins go on to the next matching rule.
func signonRuleMFADecision(r okta.PolicyRule) (covered, decided bool) {
	signon := r.Actions.Signon
	if !limitedToSomeSignIns(r.Conditions) {
		return signon.RequireFactor, true
	}
	if signon.RequireFactor || strings.EqualFold(signon.Access, AccessDeny) {
		return false, false
	}
	return false, true
}

// limitedToSomeSignIns reports whether a sign-on rule sets a condition on how
// the person signs in. These are the conditions Okta documents for sign-on
// rules, each with the value that matches every sign-in.
func limitedToSomeSignIns(c okta.PolicyRuleConditions) bool {
	narrows := func(value, matchesAll string) bool {
		return value != "" && !strings.EqualFold(value, matchesAll)
	}
	return (c.Network != nil && narrows(c.Network.Connection, "ANYWHERE")) ||
		(c.AuthContext != nil && narrows(c.AuthContext.AuthType, "ANY")) ||
		(c.IdentityProvider != nil && narrows(c.IdentityProvider.Provider, "ANY")) ||
		(c.RiskScore != nil && narrows(c.RiskScore.Level, "ANY")) ||
		(c.Risk != nil && len(c.Risk.Behaviors) > 0)
}

// enrollRuleRequiresFactor reports whether an enrollment rule is set to
// LOGIN, where users enroll when they sign in. Under a rule set to CHALLENGE,
// users enroll the next time a sign-on rule requires MFA. That rule adds no
// requirement of its own.
func enrollRuleRequiresFactor(r okta.PolicyRule) bool {
	return strings.EqualFold(r.Actions.Enroll.Self, MFAActionLogin)
}

func matchesPeopleCondition(userID string, people *okta.PolicyPeopleCondition, groupMembers groupMembership) bool {
	if people == nil {
		return true
	}

	included := !hasPeopleIncludes(people)
	if people.Users != nil && containsString(people.Users.Include, userID) {
		included = true
	}
	if people.Groups != nil && groupMembers.userInAny(userID, people.Groups.Include) {
		included = true
	}
	if !included {
		return false
	}

	if people.Users != nil && containsString(people.Users.Exclude, userID) {
		return false
	}
	if people.Groups != nil && groupMembers.userInAny(userID, people.Groups.Exclude) {
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
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

// userCoveredByManagedDeviceRequirement reports whether the first sign-on
// rule that matches the user, of any action type, has a managed-device
// condition.
func userCoveredByManagedDeviceRequirement(userID string, signOnPolicies []scopedPolicy, groupMembers groupMembership) bool {
	return firstMatchingRuleDecides(userID, signOnPolicies, groupMembers, anyRule, alwaysDecides(ruleRequiresManagedDevice))
}

// ruleRequiresManagedDevice checks if a policy rule has a managed device condition.
func ruleRequiresManagedDevice(rule okta.PolicyRule) bool {
	if rule.Conditions.Device == nil {
		return false
	}
	return strings.EqualFold(rule.Conditions.Device.Managed, "true")
}

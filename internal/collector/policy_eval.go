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

// signOnPolicyRequiresMFA and mfaEnrollmentPolicyRequiresMFA both follow
// "first matching policy decides": the highest-priority policy that applies to
// the user governs, and within it the first matching rule's action is the answer.
func signOnPolicyRequiresMFA(userID string, policies []scopedPolicy, groupMembers groupMembership) bool {
	return firstMatchingPolicyDecides(userID, policies, groupMembers, ruleHasSignonAction, signonRuleRequiresFactor)
}

func mfaEnrollmentPolicyRequiresMFA(userID string, policies []scopedPolicy, groupMembers groupMembership) bool {
	return firstMatchingPolicyDecides(userID, policies, groupMembers, ruleHasEnrollAction, enrollRuleRequiresFactor)
}

// firstMatchingPolicyDecides returns the result of the first policy whose
// people-condition matches the user; that policy's first matching in-scope rule
// determines the answer. Later policies are not consulted.
func firstMatchingPolicyDecides(userID string, policies []scopedPolicy, groupMembers groupMembership, inScope, predicate func(okta.PolicyRule) bool) bool {
	for _, sp := range policies {
		if !matchesPeopleCondition(userID, sp.policy.Conditions.People, groupMembers) {
			continue
		}
		return firstMatchingRule(userID, sp.rules, groupMembers, inScope, predicate)
	}
	return false
}

// firstMatchingRule returns predicate(rule) for the first active rule that is in
// scope and whose people-condition matches the user; false if none match. inScope
// filters which rules participate (e.g. only sign-on rules); predicate computes
// the result for that first matching rule.
func firstMatchingRule(userID string, rules []okta.PolicyRule, groupMembers groupMembership, inScope, predicate func(okta.PolicyRule) bool) bool {
	for _, rule := range rules {
		if rule.Status != StatusActive || !inScope(rule) {
			continue
		}
		if !matchesPeopleCondition(userID, rule.Conditions.People, groupMembers) {
			continue
		}
		return predicate(rule)
	}
	return false
}

// Rule scope filters and result predicates passed to firstMatchingRule.
func ruleHasSignonAction(r okta.PolicyRule) bool { return r.Actions.Signon != nil }
func ruleHasEnrollAction(r okta.PolicyRule) bool { return r.Actions.Enroll != nil }
func anyRule(okta.PolicyRule) bool               { return true }

func signonRuleRequiresFactor(r okta.PolicyRule) bool { return r.Actions.Signon.RequireFactor }

func enrollRuleRequiresFactor(r okta.PolicyRule) bool {
	action := strings.ToUpper(r.Actions.Enroll.Self)
	return action == MFAActionChallenge || action == MFAActionLogin
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

// userCoveredByManagedDeviceRequirement reports whether the user is covered by a
// managed-device requirement. Like the MFA walk, it follows Okta's "first
// matching policy decides" precedence: the highest-priority sign-on policy that
// applies to the user governs, and within it the first matching rule (of any
// action type) determines the requirement. Lower-priority policies Okta would
// not apply do not count.
func userCoveredByManagedDeviceRequirement(userID string, signOnPolicies []scopedPolicy, groupMembers groupMembership) bool {
	return firstMatchingPolicyDecides(userID, signOnPolicies, groupMembers, anyRule, ruleRequiresManagedDevice)
}

// ruleRequiresManagedDevice checks if a policy rule has a managed device condition.
func ruleRequiresManagedDevice(rule okta.PolicyRule) bool {
	if rule.Conditions.Device == nil {
		return false
	}
	return strings.EqualFold(rule.Conditions.Device.Managed, "true")
}

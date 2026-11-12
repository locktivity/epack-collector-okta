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

// userCoveredByMFARequirement reports whether every sign-in of the user
// must use MFA or is blocked. With exclusions false, the walk ignores the
// users and groups that policies and rules exclude by name, which is how
// mfa_required treats named exceptions.
func userCoveredByMFARequirement(userID string, signOnPolicies []scopedPolicy, groupMembers groupMembership, exclusions bool) bool {
	return everySignInSettled(userID, signOnPolicies, groupMembers, exclusions, anyRule, ruleRequiresMFAOrBlocks)
}

// userCoveredByManagedDeviceRequirement reports whether the user can sign in
// from a managed device and every sign-in of theirs from another device is
// blocked. A rule limited to managed devices never sees the other sign-ins,
// and the walk notes whether one lets the user in before the others are all
// blocked. A user blocked everywhere is not required to use a managed
// device, since no device lets them in.
func userCoveredByManagedDeviceRequirement(userID string, signOnPolicies []scopedPolicy, groupMembers groupMembership) bool {
	managedLetIn := false
	sees := func(r okta.PolicyRule) bool {
		if limitedToManagedDevices(r) {
			managedLetIn = managedLetIn || !ruleBlocks(r)
			return false
		}
		return true
	}
	return everySignInSettled(userID, signOnPolicies, groupMembers, true, sees, ruleBlocks) && managedLetIn
}

// everySignInSettled follows Okta's evaluation order for sign-on policies.
// Policies that apply to the user are evaluated in priority order, and so
// are the active rules of each. A rule applies to the sign-ins that meet
// its conditions, and settled says whether it settles them, such as by
// requiring MFA. The sign-ins it does not apply to go on to the next rule,
// and past a policy's last rule to the next policy. The result is true once
// the settled rules together apply to every sign-in, and false at the first
// rule that lets some sign-ins in unsettled, or when the rules run out.
// sees picks the rules that can apply to the sign-ins in question.
func everySignInSettled(userID string, policies []scopedPolicy, groupMembers groupMembership, exclusions bool, sees, settled func(okta.PolicyRule) bool) bool {
	var settledSoFar signIns
	for _, sp := range policies {
		if !matchesPeople(userID, sp.policy.Conditions.People, groupMembers, exclusions) {
			continue
		}
		for _, rule := range sp.rules {
			if rule.Status != StatusActive || rule.Actions.Signon == nil {
				continue
			}
			if !matchesPeople(userID, rule.Conditions.People, groupMembers, exclusions) || !sees(rule) {
				continue
			}
			if !settled(rule) {
				return false
			}
			if settledSoFar.add(rule.Conditions); settledSoFar.all() {
				return true
			}
		}
	}
	return false
}

// ruleDecision gives the result for a rule that matches the user. decided is
// false when the rule settles only some of the user's sign-ins, and the next
// matching rule settles the others.
type ruleDecision func(okta.PolicyRule) (covered, decided bool)

// firstMatchingRuleDecides walks the policies whose people condition matches
// the user, in order, and their active in-scope rules whose people condition
// matches the user. The first rule that decides gives the result. A policy
// with no such rule leaves the user to the next policy, and the result is
// false when no rule decides. inScope picks the rules that take part.
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

func anyRule(okta.PolicyRule) bool { return true }

// ruleRequiresMFAOrBlocks reports whether a sign-on rule settles its
// sign-ins for MFA: it requires a factor, or denies access, since a blocked
// sign-in cannot skip MFA.
func ruleRequiresMFAOrBlocks(r okta.PolicyRule) bool {
	return r.Actions.Signon.RequireFactor || ruleBlocks(r)
}

func ruleBlocks(r okta.PolicyRule) bool {
	return strings.EqualFold(r.Actions.Signon.Access, AccessDeny)
}

func limitedToManagedDevices(r okta.PolicyRule) bool {
	d := r.Conditions.Device
	return d != nil && strings.EqualFold(d.Managed, "true")
}

// limitedToSomeSignIns reports whether a rule sets a condition on how the
// person signs in. These are the conditions Okta documents for sign-on
// rules, each with the value that matches every sign-in, and the device
// condition of a Classic Engine sign-on rule.
func limitedToSomeSignIns(c okta.PolicyRuleConditions) bool {
	narrows := func(value, matchesAll string) bool {
		return value != "" && !strings.EqualFold(value, matchesAll)
	}
	return (c.Network != nil && narrows(c.Network.Connection, "ANYWHERE")) ||
		(c.AuthContext != nil && narrows(c.AuthContext.AuthType, "ANY")) ||
		(c.IdentityProvider != nil && narrows(c.IdentityProvider.Provider, "ANY")) ||
		(c.RiskScore != nil && narrows(c.RiskScore.Level, "ANY")) ||
		(c.Risk != nil && len(c.Risk.Behaviors) > 0) ||
		(c.Device != nil && (strings.EqualFold(c.Device.Managed, "true") || strings.EqualFold(c.Device.Registered, "true") ||
			(c.Device.Assurance != nil && len(c.Device.Assurance.Include) > 0)))
}

// onNetwork stands for the sign-ins Okta's ON_NETWORK connection matches,
// as if it were a zone. OFF_NETWORK matches the rest.
const onNetwork = "ON_NETWORK"

// signIns tracks the sign-ins that settled rules apply to. A rule limited
// by its network location alone adds the sign-ins from the zones it
// includes, or from outside the zones it excludes. A rule limited in any
// other way adds none, since which of its sign-ins other rules also reach
// is not tracked.
type signIns struct {
	everywhere bool
	inside     map[string]bool // zones whose sign-ins are settled
	excluded   map[string]bool // zones in every exclude list added; sign-ins outside them are settled
	excludes   bool            // whether any exclude list was added
}

func (s *signIns) add(c okta.PolicyRuleConditions) {
	if !limitedToSomeSignIns(c) {
		s.everywhere = true
		return
	}
	network := c.Network
	c.Network = nil
	if network == nil || limitedToSomeSignIns(c) {
		return
	}
	switch strings.ToUpper(network.Connection) {
	case "ON_NETWORK":
		s.addInside(onNetwork)
	case "OFF_NETWORK":
		s.addOutside(onNetwork)
	case "ZONE":
		switch {
		case len(network.Include) > 0 && len(network.Exclude) == 0:
			s.addInside(network.Include...)
		case len(network.Exclude) > 0 && len(network.Include) == 0:
			s.addOutside(network.Exclude...)
		}
	}
}

func (s *signIns) addInside(zones ...string) {
	if s.inside == nil {
		s.inside = map[string]bool{}
	}
	for _, z := range zones {
		s.inside[z] = true
	}
}

// addOutside adds the sign-ins from outside zones. Those from outside every
// exclude list added are the sign-ins from outside the zones all the lists
// name.
func (s *signIns) addOutside(zones ...string) {
	names := make(map[string]bool, len(zones))
	for _, z := range zones {
		names[z] = !s.excludes || s.excluded[z]
	}
	s.excluded = map[string]bool{}
	for z, inAll := range names {
		if inAll {
			s.excluded[z] = true
		}
	}
	s.excludes = true
}

// all reports whether the settled rules apply to every sign-in.
func (s *signIns) all() bool {
	if s.everywhere {
		return true
	}
	if !s.excludes {
		return false
	}
	for z := range s.excluded {
		if !s.inside[z] {
			return false
		}
	}
	return true
}

func matchesPeopleCondition(userID string, people *okta.PolicyPeopleCondition, groupMembers groupMembership) bool {
	return matchesPeople(userID, people, groupMembers, true)
}

// matchesPeople reports whether a people condition matches the user. With
// exclusions false, the users and groups it excludes are ignored.
func matchesPeople(userID string, people *okta.PolicyPeopleCondition, groupMembers groupMembership, exclusions bool) bool {
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
	if !exclusions {
		return true
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

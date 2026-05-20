package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-okta/internal/okta"
)

// Characterization tests for the per-user coverage engine. They pin the CURRENT
// behavior, including the two ways the MFA and managed-device walks deliberately
// differ, so a later refactor that unifies the shared rule-walk cannot silently
// change a customer's coverage result.

// --- fixture builders ---

// peopleGroups builds a people-condition scoping a policy/rule to the given
// include / exclude group IDs.
func peopleGroups(include, exclude []string) *okta.PolicyPeopleCondition {
	p := &okta.PolicyPeopleCondition{}
	p.Groups = &struct {
		Include []string `json:"include,omitempty"`
		Exclude []string `json:"exclude,omitempty"`
	}{Include: include, Exclude: exclude}
	return p
}

func peopleUsers(include, exclude []string) *okta.PolicyPeopleCondition {
	p := &okta.PolicyPeopleCondition{}
	p.Users = &struct {
		Include []string `json:"include,omitempty"`
		Exclude []string `json:"exclude,omitempty"`
	}{Include: include, Exclude: exclude}
	return p
}

// everyonePolicy is a scoped policy with no people-condition (applies to all).
func everyonePolicy(rules ...okta.PolicyRule) scopedPolicy {
	return scopedPolicy{policy: okta.Policy{Status: StatusActive}, rules: rules}
}

func scopedTo(people *okta.PolicyPeopleCondition, rules ...okta.PolicyRule) scopedPolicy {
	return scopedPolicy{
		policy: okta.Policy{Status: StatusActive, Conditions: okta.PolicyConditions{People: people}},
		rules:  rules,
	}
}

func signonRule(status string, requireFactor bool) okta.PolicyRule {
	return okta.PolicyRule{Status: status, Actions: okta.PolicyRuleActions{Signon: &okta.SignonActions{RequireFactor: requireFactor}}}
}

func enrollRule(status, self string) okta.PolicyRule {
	return okta.PolicyRule{Status: status, Actions: okta.PolicyRuleActions{Enroll: &okta.EnrollActions{Self: self}}}
}

// deviceOnlyRule is active and people-matching but carries no sign-on action,
// only a managed-device condition.
func deviceOnlyRule(managed string) okta.PolicyRule {
	return okta.PolicyRule{Status: StatusActive, Conditions: okta.PolicyRuleConditions{Device: &okta.DeviceCondition{Managed: managed}}}
}

func signonDeviceRule(managed string) okta.PolicyRule {
	return okta.PolicyRule{
		Status:     StatusActive,
		Conditions: okta.PolicyRuleConditions{Device: &okta.DeviceCondition{Managed: managed}},
		Actions:    okta.PolicyRuleActions{Signon: &okta.SignonActions{}},
	}
}

const u = "user-1"

func noGroups() groupMembership { return groupMembership{} }

// --- MFA coverage ---

func TestMFACoverage_SignOnFirstActiveRuleRequiresFactor(t *testing.T) {
	policies := []scopedPolicy{everyonePolicy(signonRule(StatusActive, true))}
	if !userCoveredByMFARequirement(u, policies, nil, noGroups()) {
		t.Error("expected MFA required when first active sign-on rule requires a factor")
	}
}

func TestMFACoverage_FirstMatchingPolicyDecides(t *testing.T) {
	// Two matching policies: the first says no-MFA, the second would say MFA.
	// The MFA walk returns on the FIRST matching policy, so the result is false.
	policies := []scopedPolicy{
		everyonePolicy(signonRule(StatusActive, false)),
		everyonePolicy(signonRule(StatusActive, true)),
	}
	if userCoveredByMFARequirement(u, policies, nil, noGroups()) {
		t.Error("expected false: the first matching policy decides, even though a later policy requires MFA")
	}
}

func TestMFACoverage_SkipsRuleWithoutSignonAction(t *testing.T) {
	// A rule with no Signon action is out of scope; the next sign-on rule decides.
	deviceOnly := deviceOnlyRule("true")
	policies := []scopedPolicy{everyonePolicy(deviceOnly, signonRule(StatusActive, true))}
	if !userCoveredByMFARequirement(u, policies, nil, noGroups()) {
		t.Error("expected the non-sign-on rule to be skipped and the sign-on rule to decide (true)")
	}
}

func TestMFACoverage_InactiveRuleSkipped(t *testing.T) {
	policies := []scopedPolicy{everyonePolicy(signonRule("INACTIVE", true), signonRule(StatusActive, false))}
	if userCoveredByMFARequirement(u, policies, nil, noGroups()) {
		t.Error("expected inactive rule skipped; first active rule (false) decides")
	}
}

func TestMFACoverage_EnrollChallengeOrLogin(t *testing.T) {
	for _, action := range []string{"CHALLENGE", "LOGIN", "challenge"} {
		enroll := []scopedPolicy{everyonePolicy(enrollRule(StatusActive, action))}
		if !userCoveredByMFARequirement(u, nil, enroll, noGroups()) {
			t.Errorf("expected MFA required for enroll action %q", action)
		}
	}
	enrollNever := []scopedPolicy{everyonePolicy(enrollRule(StatusActive, "NEVER"))}
	if userCoveredByMFARequirement(u, nil, enrollNever, noGroups()) {
		t.Error("expected no MFA for enroll action NEVER")
	}
}

func TestMFACoverage_GroupIncludeAndExclude(t *testing.T) {
	gm := groupMembership{"admins": {u: {}}}

	included := []scopedPolicy{scopedTo(peopleGroups([]string{"admins"}, nil), signonRule(StatusActive, true))}
	if !userCoveredByMFARequirement(u, included, nil, gm) {
		t.Error("expected coverage when user is in an included group")
	}

	excluded := []scopedPolicy{scopedTo(peopleGroups([]string{"admins"}, []string{"admins"}), signonRule(StatusActive, true))}
	if userCoveredByMFARequirement(u, excluded, nil, gm) {
		t.Error("expected exclude to win over include, so the policy does not apply")
	}
}

func TestMFACoverage_UserIncludeMatches(t *testing.T) {
	policies := []scopedPolicy{scopedTo(peopleUsers([]string{u}, nil), signonRule(StatusActive, true))}
	if !userCoveredByMFARequirement(u, policies, nil, noGroups()) {
		t.Error("expected coverage when user is directly included")
	}
}

func TestMFACoverage_NoPolicies(t *testing.T) {
	if userCoveredByMFARequirement(u, nil, nil, noGroups()) {
		t.Error("expected no coverage with no policies")
	}
}

// --- managed-device coverage ---

func TestManagedDevice_FirstMatchingPolicyDecides(t *testing.T) {
	// Okta applies only the highest-priority matching policy of a given type. The
	// first matching policy does not require a managed device, so even though a
	// lower-priority policy would, the user is NOT covered (that policy never
	// applies). Mirrors TestMFACoverage_FirstMatchingPolicyDecides.
	policies := []scopedPolicy{
		everyonePolicy(signonDeviceRule("false")),
		everyonePolicy(signonDeviceRule("true")),
	}
	if userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
		t.Error("expected false: only the first matching policy governs; lower-priority policies do not apply")
	}
}

func TestManagedDevice_NoActionFilterOnFirstMatchingRule(t *testing.T) {
	// The first active, people-matching rule decides regardless of action type.
	// A rule with no sign-on action but a managed-device condition counts.
	policies := []scopedPolicy{everyonePolicy(deviceOnlyRule("true"))}
	if !userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
		t.Error("expected the first matching rule to decide even with no sign-on action")
	}
}

func TestManagedDevice_FirstMatchingRuleWithoutDeviceWins(t *testing.T) {
	// First matching rule has no device condition -> false; a later rule that
	// requires a device does not rescue it within the same policy.
	policies := []scopedPolicy{everyonePolicy(signonRule(StatusActive, true), signonDeviceRule("true"))}
	if userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
		t.Error("expected false: the first matching rule (no device) decides within a policy")
	}
}

func TestManagedDevice_NotCovered(t *testing.T) {
	policies := []scopedPolicy{everyonePolicy(signonRule(StatusActive, true))}
	if userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
		t.Error("expected no managed-device coverage when no rule requires it")
	}
}

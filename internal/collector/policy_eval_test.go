package collector

import (
	"encoding/json"
	"testing"

	"github.com/locktivity/epack-collector-okta/internal/okta"
)

// Tests for the per-user coverage engine: the MFA walk, where a rule that
// requires a factor or blocks sign-in settles its sign-ins, and the
// managed-device walk, where a rule that blocks sign-in from a device that is
// not managed does.

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

// ruleFromJSON decodes a policy rule written as Okta's API returns it.
func ruleFromJSON(t *testing.T, doc string) okta.PolicyRule {
	t.Helper()
	var rule okta.PolicyRule
	if err := json.Unmarshal([]byte(doc), &rule); err != nil {
		t.Fatalf("decoding rule %s: %v", doc, err)
	}
	return rule
}

const u = "user-1"

func noGroups() groupMembership { return groupMembership{} }

// --- MFA coverage ---

func TestMFACoverage_SignOnFirstActiveRuleRequiresFactor(t *testing.T) {
	policies := []scopedPolicy{everyonePolicy(signonRule(StatusActive, true))}
	if !userCoveredByMFARequirement(u, policies, noGroups(), true) {
		t.Error("expected MFA required when first active sign-on rule requires a factor")
	}
}

func TestMFACoverage_FirstMatchingPolicyDecides(t *testing.T) {
	// Two matching policies: the first says no-MFA, the second would say MFA.
	// The first policy has a rule that applies, so the result is false.
	policies := []scopedPolicy{
		everyonePolicy(signonRule(StatusActive, false)),
		everyonePolicy(signonRule(StatusActive, true)),
	}
	if userCoveredByMFARequirement(u, policies, noGroups(), true) {
		t.Error("expected false: the first matching policy decides, even though a later policy requires MFA")
	}
}

func TestMFACoverage_SkipsRuleWithoutSignonAction(t *testing.T) {
	// A rule with no Signon action is out of scope; the next sign-on rule decides.
	deviceOnly := deviceOnlyRule("true")
	policies := []scopedPolicy{everyonePolicy(deviceOnly, signonRule(StatusActive, true))}
	if !userCoveredByMFARequirement(u, policies, noGroups(), true) {
		t.Error("expected the non-sign-on rule to be skipped and the sign-on rule to decide (true)")
	}
}

func TestMFACoverage_InactiveRuleSkipped(t *testing.T) {
	policies := []scopedPolicy{everyonePolicy(signonRule("INACTIVE", true), signonRule(StatusActive, false))}
	if userCoveredByMFARequirement(u, policies, noGroups(), true) {
		t.Error("expected inactive rule skipped; first active rule (false) decides")
	}
}

func TestMFACoverage_DenyRuleSettles(t *testing.T) {
	deny := okta.PolicyRule{Status: StatusActive, Actions: okta.PolicyRuleActions{Signon: &okta.SignonActions{Access: AccessDeny}}}
	if !userCoveredByMFARequirement(u, []scopedPolicy{everyonePolicy(deny, signonRule(StatusActive, false))}, noGroups(), true) {
		t.Error("expected a rule that blocks every sign-in to count as covered")
	}
}

func TestMFACoverage_ExclusionsSetAside(t *testing.T) {
	gm := groupMembership{"breakglass": {u: {}}}
	mfa := signonRule(StatusActive, true)
	mfa.Conditions.People = peopleGroups(nil, []string{"breakglass"})
	policies := []scopedPolicy{everyonePolicy(mfa, signonRule(StatusActive, false))}
	if userCoveredByMFARequirement(u, policies, gm, true) {
		t.Error("expected the excluded user not covered")
	}
	if !userCoveredByMFARequirement(u, policies, gm, false) {
		t.Error("expected the user covered once the exclusion is set aside")
	}
}

func TestMFACoverage_NextPolicyWhenNoRuleApplies(t *testing.T) {
	gm := groupMembership{"admins": {u: {}}}
	inactiveOnly := scopedTo(peopleGroups([]string{"admins"}, nil), signonRule("INACTIVE", false))
	excludedRule := signonRule(StatusActive, false)
	excludedRule.Conditions.People = peopleUsers(nil, []string{u})
	excludedOnly := scopedTo(peopleGroups([]string{"admins"}, nil), excludedRule)
	requiresMFA := everyonePolicy(signonRule(StatusActive, true))

	for name, first := range map[string]scopedPolicy{"only an inactive rule": inactiveOnly, "only a rule that excludes the user": excludedOnly} {
		if !userCoveredByMFARequirement(u, []scopedPolicy{first, requiresMFA}, gm, true) {
			t.Errorf("first policy with %s: expected the next policy's MFA rule to apply", name)
		}
	}
}

func TestMFACoverage_RuleForSomeNetworkZones(t *testing.T) {
	// MFA away from the office, above a rule with no MFA for everyone else.
	offOffice := ruleFromJSON(t, `{"status":"ACTIVE","conditions":{"network":{"connection":"ZONE","exclude":["nzoOffice"]}},
		"actions":{"signon":{"access":"ALLOW","requireFactor":true}}}`)
	anywhere := ruleFromJSON(t, `{"status":"ACTIVE","conditions":{"network":{"connection":"ANYWHERE"}},
		"actions":{"signon":{"access":"ALLOW","requireFactor":false}}}`)
	if userCoveredByMFARequirement(u, []scopedPolicy{everyonePolicy(offOffice, anywhere)}, noGroups(), true) {
		t.Error("expected no MFA, since sign-ins from the office reach the rule with no MFA")
	}

	// A rule that denies sign-in from some zones, above a rule that requires MFA.
	denyZone := ruleFromJSON(t, `{"status":"ACTIVE","conditions":{"network":{"connection":"ZONE","include":["nzoBlocked"]}},
		"actions":{"signon":{"access":"DENY","requireFactor":false}}}`)
	anywhereMFA := ruleFromJSON(t, `{"status":"ACTIVE","conditions":{"network":{"connection":"ANYWHERE"}},
		"actions":{"signon":{"access":"ALLOW","requireFactor":true}}}`)
	if !userCoveredByMFARequirement(u, []scopedPolicy{everyonePolicy(denyZone, anywhereMFA)}, noGroups(), true) {
		t.Error("expected MFA required, since every sign-in the deny rule allows reaches the MFA rule")
	}

	// A zone rule with MFA is the policy's only rule, so other sign-ins move
	// to the next policy.
	noMFA := everyonePolicy(signonRule(StatusActive, false))
	if userCoveredByMFARequirement(u, []scopedPolicy{everyonePolicy(offOffice), noMFA}, noGroups(), true) {
		t.Error("expected no MFA, since sign-ins from the office reach the next policy's rule with no MFA")
	}
}

func TestLimitedToSomeSignIns(t *testing.T) {
	tests := []struct {
		conditions string
		want       bool
	}{
		// The conditions Okta returns on a rule that applies to every sign-in.
		{`{"people":{"users":{"exclude":[]}},"network":{"connection":"ANYWHERE"},"authContext":{"authType":"ANY"},
			"risk":{"behaviors":[]},"riskScore":{"level":"ANY"},"identityProvider":{"provider":"ANY"}}`, false},
		{`{}`, false},
		{`{"network":{"connection":"ZONE","include":["nzo1"]}}`, true},
		{`{"authContext":{"authType":"RADIUS"}}`, true},
		{`{"identityProvider":{"provider":"OKTA"}}`, true},
		{`{"risk":{"behaviors":["New Device"]}}`, true},
		{`{"riskScore":{"level":"HIGH"}}`, true},
		{`{"device":{"managed":true,"registered":true}}`, true},
		{`{"device":{"registered":true}}`, true},
		{`{"device":{"assurance":{"include":["dae1"]}}}`, true},
		{`{"device":{"managed":false,"registered":false}}`, false},
	}
	for _, tt := range tests {
		rule := ruleFromJSON(t, `{"conditions":`+tt.conditions+`}`)
		if got := limitedToSomeSignIns(rule.Conditions); got != tt.want {
			t.Errorf("limitedToSomeSignIns(%s) = %v, want %v", tt.conditions, got, tt.want)
		}
	}
}

func TestMFACoverage_GroupIncludeAndExclude(t *testing.T) {
	gm := groupMembership{"admins": {u: {}}}

	included := []scopedPolicy{scopedTo(peopleGroups([]string{"admins"}, nil), signonRule(StatusActive, true))}
	if !userCoveredByMFARequirement(u, included, gm, true) {
		t.Error("expected coverage when user is in an included group")
	}

	excluded := []scopedPolicy{scopedTo(peopleGroups([]string{"admins"}, []string{"admins"}), signonRule(StatusActive, true))}
	if userCoveredByMFARequirement(u, excluded, gm, true) {
		t.Error("expected exclude to win over include, so the policy does not apply")
	}
}

func TestMFACoverage_UserIncludeMatches(t *testing.T) {
	policies := []scopedPolicy{scopedTo(peopleUsers([]string{u}, nil), signonRule(StatusActive, true))}
	if !userCoveredByMFARequirement(u, policies, noGroups(), true) {
		t.Error("expected coverage when user is directly included")
	}
}

func TestMFACoverage_NoPolicies(t *testing.T) {
	if userCoveredByMFARequirement(u, nil, noGroups(), true) {
		t.Error("expected no coverage with no policies")
	}
}

// --- managed-device coverage ---

func denySignonRule() okta.PolicyRule {
	return okta.PolicyRule{Status: StatusActive, Actions: okta.PolicyRuleActions{Signon: &okta.SignonActions{Access: AccessDeny}}}
}

func TestManagedDevice_OtherDevicesBlocked(t *testing.T) {
	policies := []scopedPolicy{everyonePolicy(signonDeviceRule("true"), denySignonRule())}
	if !userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
		t.Error("expected coverage when sign-ins from other devices are blocked")
	}
}

func TestManagedDevice_BlockedEverywhere(t *testing.T) {
	// No device lets the user in, so a managed device is not what access
	// requires.
	for name, policies := range map[string][]scopedPolicy{
		"no managed-device rule":      {everyonePolicy(denySignonRule())},
		"managed devices blocked too": {everyonePolicy(denySignonRule(), signonDeviceRule("true"))},
		"managed-device rule for others": {everyonePolicy(func() okta.PolicyRule {
			r := signonDeviceRule("true")
			r.Conditions.People = peopleUsers([]string{"someone-else"}, nil)
			return r
		}(), denySignonRule())},
	} {
		if userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
			t.Errorf("%s: expected no coverage when no device lets the user in", name)
		}
	}
}

func TestManagedDevice_OtherDevicesGetIn(t *testing.T) {
	// A rule for managed devices first, and every other device let in by
	// the next rule, even with MFA.
	policies := []scopedPolicy{everyonePolicy(signonDeviceRule("true"), signonRule(StatusActive, true))}
	if userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
		t.Error("expected no coverage when sign-ins from other devices get in")
	}
}

func TestManagedDevice_NoRuleForOtherDevices(t *testing.T) {
	policies := []scopedPolicy{everyonePolicy(signonDeviceRule("true"))}
	if userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
		t.Error("expected no coverage when no rule settles sign-ins from other devices")
	}
}

func TestManagedDevice_FirstMatchingPolicyDecides(t *testing.T) {
	// The first matching policy lets in sign-ins from any device. A later
	// policy that blocks them is never reached.
	policies := []scopedPolicy{
		everyonePolicy(signonDeviceRule("false")),
		everyonePolicy(denySignonRule()),
	}
	if userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
		t.Error("expected false: the first matching policy lets other devices in")
	}
}

func TestManagedDevice_NextPolicyWhenNoRuleApplies(t *testing.T) {
	gm := groupMembership{"admins": {u: {}}}
	policies := []scopedPolicy{
		scopedTo(peopleGroups([]string{"admins"}, nil), signonDeviceRule("true")),
		everyonePolicy(denySignonRule()),
	}
	if !userCoveredByManagedDeviceRequirement(u, policies, gm) {
		t.Error("expected the next policy to block sign-ins from other devices")
	}
}

func TestManagedDevice_SkipsRuleWithoutSignonAction(t *testing.T) {
	policies := []scopedPolicy{everyonePolicy(deviceOnlyRule("false"), signonDeviceRule("true"), denySignonRule())}
	if !userCoveredByManagedDeviceRequirement(u, policies, noGroups()) {
		t.Error("expected the rule with no sign-on action to be skipped")
	}
}

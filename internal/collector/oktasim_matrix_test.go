package collector

import (
	"encoding/json"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated matrix varies the sandbox along the axes below. Each
// one-at-a-time row changes one setting, so a difference it shows belongs to
// that setting and is listed in simMatrixAlone. The pairwise rows put every
// two settings together at least once, and a difference none of a row's
// settings shows alone must be listed in simMatrixTogether.

// simMatrixAdmin is an account the matrix adds, an enabled member with
// Okta Verify push who signed in three days ago, in no sandbox group, so
// the Sandbox everyone else policy decides its sign-ins, and with no role
// until the role axis gives it one.
const simMatrixAdmin = "matrix_admin"

// simEveryoneRule is the rule of the Sandbox everyone else policy.
const simEveryoneRule = "everyone_else/everyone_else"

// simMatrixBase is the sandbox with no app sign-in policies, so the
// collector writes the MFA requirement, and without the suspended and
// staged users and the read-only role, whose differences the scenarios
// list, so a row's differences are its own.
func simMatrixBase(t testing.TB) *roster.Roster {
	t.Helper()
	reals, err := simBase(t).Realizations()
	if err != nil {
		t.Fatal(err)
	}
	r := withoutAppSignInPolicies(reals[0].Roster)
	gone := []string{"admin_suspended", "svc_staged"}
	r.Accounts = slices.DeleteFunc(r.Accounts, func(a roster.Account) bool { return slices.Contains(gone, a.Key) })
	for i := range r.Groups {
		r.Groups[i].Members = slices.DeleteFunc(r.Groups[i].Members, func(k string) bool { return slices.Contains(gone, k) })
		if r.Groups[i].Key == "readonly_admins" {
			r.Groups[i].Roles = nil
		}
	}
	r.Terms.Conditions = map[string]map[string][]string{
		"on_network":  {roster.PartLocation: {"trusted"}},
		"off_network": {roster.PartLocation: {"untrusted"}},
		"risk_high":   {roster.PartSignInRisk: {"high"}},
		"radius":      {roster.PartClient: {roster.ClientLegacy}},
	}
	r.Terms.Roles["Help Desk Lite"], r.Terms.Roles["User Manager"] = roster.RoleNone, roster.RoleAdmin
	simulate.SetExtra(&r.Extra, "custom_roles", map[string]any{
		"Help Desk Lite": map[string]any{"permissions": []string{"okta.users.read"}},
		"User Manager":   map[string]any{"permissions": []string{"okta.users.read", "okta.users.manage"}},
	})
	r.Accounts = append(r.Accounts, roster.Account{Key: simMatrixAdmin, Kind: "member", Enabled: true, Methods: []string{"push"}, SignedInDaysAgo: intPtr(3)})
	r.Groups = append(r.Groups, roster.Group{Key: "matrix_group", Members: []string{simMatrixAdmin}})
	return validated(t, r)
}

func onAdmin(change func(*roster.Account)) func(*roster.Roster) {
	return simulate.OnAccount(simMatrixAdmin, change)
}

func onEveryone(change func(*roster.Policy)) func(*roster.Roster) {
	return simulate.OnPolicy(simEveryoneRule, change)
}

func status(s string, enabled bool) func(*roster.Account) {
	return func(a *roster.Account) {
		a.Enabled, a.State = enabled, s
	}
}

// addRule adds a rule to the Sandbox everyone else policy at rule
// priority, after moving the policy's own rule to moved.
func addRule(key string, priority, moved int, change func(*roster.Policy)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		i := slices.IndexFunc(r.Policies, func(p roster.Policy) bool { return p.Key == simEveryoneRule })
		rule := r.Policies[i]
		setRulePriority(&r.Policies[i], moved)
		rule.Key, rule.Conditions, rule.Exclude = "everyone_else/"+key, nil, roster.Audience{}
		simulate.SetExtra(&rule.Extra, "rule", map[string]any{"name": key, "priority": priority, "idle_minutes": 120, "lifetime_minutes": 720})
		setRulePriority(&rule, priority)
		change(&rule)
		r.Policies = append(r.Policies, rule)
	}
}

// setRulePriority moves a sign-on rule within its policy.
func setRulePriority(p *roster.Policy, priority int) {
	var rule map[string]any
	simulate.Extra(p.Extra, "rule", &rule)
	rule["priority"] = priority
	simulate.SetExtra(&p.Extra, "rule", rule)
	p.Priority = p.Priority/100*100 + priority
}

// setPolicyPriority moves a global session policy and its rules.
func setPolicyPriority(r *roster.Roster, key string, priority int) {
	var policies map[string]simPolicy
	simulate.Extra(r.Extra, "sign_on_policies", &policies)
	p := policies[key]
	p.Priority = priority
	policies[key] = p
	simulate.SetExtra(&r.Extra, "sign_on_policies", policies)
	for i := range r.Policies {
		var of string
		simulate.Extra(r.Policies[i].Extra, "policy", &of)
		if of == key {
			r.Policies[i].Priority = priority*100 + r.Policies[i].Priority%100
		}
	}
}

// partner gives the roster the partner identity provider, then makes the
// changes.
func partner(idp simIdP, changes ...func(*roster.Roster)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		simulate.SetExtra(&r.Extra, "identity_providers", map[string]simIdP{simPartner: idp})
		for _, change := range changes {
			change(r)
		}
	}
}

// setEnroll sets an enrollment rule's action.
func setEnroll(policy, rule, enroll string) func(*roster.Roster) {
	return func(r *roster.Roster) {
		var policies map[string]simPolicy
		simulate.Extra(r.Extra, "enrollment_policies", &policies)
		p := policies[policy]
		rl := p.Rules[rule]
		rl.Enroll = enroll
		p.Rules[rule] = rl
		simulate.SetExtra(&r.Extra, "enrollment_policies", policies)
	}
}

func simMatrixAxes() []roster.Axis {
	roles := []roster.Value{{Name: "none"}}
	for _, role := range []string{"SUPER_ADMIN", "ORG_ADMIN", "APP_ADMIN", "USER_ADMIN", "HELP_DESK_ADMIN", "GROUP_MEMBERSHIP_ADMIN",
		"API_ACCESS_MANAGEMENT_ADMIN", "MOBILE_ADMIN", "REPORT_ADMIN", "READ_ONLY_ADMIN", "Help Desk Lite", "User Manager"} {
		roles = append(roles, roster.Value{Name: role, Change: onAdmin(func(a *roster.Account) { a.Roles = []string{role} })})
	}
	methods := []roster.Value{{Name: "push"}, {Name: "none", Change: onAdmin(func(a *roster.Account) { a.Methods = nil })}}
	for _, m := range []string{"email", "sms", "question", "token:software:totp", "webauthn", "u2f", "signed_nonce"} {
		methods = append(methods, roster.Value{Name: m, Change: onAdmin(func(a *roster.Account) { a.Methods = []string{m} })})
	}
	methods = append(methods,
		roster.Value{Name: "webauthn pending", Change: onAdmin(func(a *roster.Account) {
			a.Methods = nil
			simulate.SetExtra(&a.Extra, "pending_factors", []string{"webauthn"})
		})},
		roster.Value{Name: "question and push", Change: onAdmin(func(a *roster.Account) { a.Methods = []string{"question", "push"} })},
	)
	conditions := []roster.Value{{Name: "none"}}
	for _, c := range []string{"on_network", "off_network", "risk_high", "radius", "managed_device"} {
		conditions = append(conditions, roster.Value{Name: c, Change: onEveryone(func(p *roster.Policy) { p.Conditions = []string{c} })})
	}
	password := func(p *roster.Policy) { p.Requires = nil }
	return []roster.Axis{
		{Name: "admin.role", Values: roles},
		{Name: "admin.state", Values: []roster.Value{
			{Name: "active"},
			{Name: "locked out", Change: onAdmin(status(StatusLockedOut, true))},
			{Name: "password expired", Change: onAdmin(status(StatusPasswordExpired, true))},
			{Name: "suspended", Change: onAdmin(status(StatusSuspended, false))},
			{Name: "staged", Change: onAdmin(func(a *roster.Account) { status("STAGED", false)(a); a.SignedInDaysAgo = nil })},
			{Name: "never signed in", Change: onAdmin(func(a *roster.Account) { a.SignedInDaysAgo = nil })},
			{Name: "signed in 90 days ago", Change: onAdmin(func(a *roster.Account) { a.SignedInDaysAgo = intPtr(90) })},
			{Name: "signed in 91 days ago", Change: onAdmin(func(a *roster.Account) { a.SignedInDaysAgo = intPtr(91) })},
			{Name: "role through a group", Change: func(r *roster.Roster) {
				a, _ := r.Account(simMatrixAdmin)
				simulate.OnGroup("matrix_group", func(g *roster.Group) { g.Roles = a.Roles })(r)
				onAdmin(func(a *roster.Account) { a.Roles = nil })(r)
			}},
		}},
		{Name: "admin.methods", Values: methods},
		{Name: "signon.rule", Values: []roster.Value{
			{Name: "mfa"},
			{Name: "password only", Change: onEveryone(password)},
			{Name: "deny", Change: onEveryone(func(p *roster.Policy) { p.Requires, p.Blocks = nil, "deny" })},
			{Name: "inactive", Change: onEveryone(func(p *roster.Policy) { p.State = "INACTIVE" })},
		}},
		{Name: "signon.condition", Values: conditions},
		// Rules that each cover part of the sign-ins, and between them
		// cover every one, or don't.
		{Name: "signon.split", Values: []roster.Value{
			{Name: "none"},
			{Name: "on and off network rules both require MFA", Change: func(r *roster.Roster) {
				onEveryone(func(p *roster.Policy) { p.Conditions = []string{"on_network"} })(r)
				addRule("off_network", 2, 1, func(p *roster.Policy) { p.Conditions = []string{"off_network"} })(r)
			}},
			{Name: "a password rule on the network first", Change: addRule("on_network_password", 1, 2, func(p *roster.Policy) {
				password(p)
				p.Conditions = []string{"on_network"}
			})},
			{Name: "an MFA rule for managed devices first", Change: func(r *roster.Roster) {
				onEveryone(func(p *roster.Policy) { p.Conditions = []string{"managed_device"} })(r)
				addRule("password", 2, 1, password)(r)
			}},
		}},
		{Name: "signon.exclusion", Values: []roster.Value{
			{Name: "none"},
			{Name: "the admin by user", Change: onEveryone(func(p *roster.Policy) { p.Exclude = roster.Audience{Accounts: []string{simMatrixAdmin}} })},
			{Name: "the admin's group", Change: onEveryone(func(p *roster.Policy) { p.Exclude = roster.Audience{Groups: []string{"matrix_group"}} })},
		}},
		{Name: "signon.order", Values: []roster.Value{
			{Name: "sandbox"},
			{Name: "everyone else first", Change: func(r *roster.Roster) {
				setPolicyPriority(r, "everyone_else", 1)
				setPolicyPriority(r, "mfa_required", 2)
				setPolicyPriority(r, "password_only", 3)
			}},
		}},
		{Name: "signon.rendering", Values: []roster.Value{
			{Name: "plain"},
			{Name: "bare conditions", Change: func(r *roster.Roster) {
				for i := range r.Policies {
					simulate.SetExtra(&r.Policies[i].Extra, "render", []string{"bare"})
				}
			}},
			{Name: "policies listed lowest priority first", Change: func(r *roster.Roster) { simulate.SetExtra(&r.Extra, "render", []string{"policies_reversed"}) }},
		}},
		{Name: "admin.signs_in", Values: []roster.Value{
			{Name: "okta"},
			{Name: "a partner provider for its domain", Change: partner(simIdP{Name: simPartnerName}, onAdmin(throughPartner))},
			{Name: "a partner provider for its login", Change: partner(simIdP{Name: simPartnerName}, onAdmin(func(a *roster.Account) { a.SignsInThrough = simPartner }))},
			{Name: "a partner provider from the office", Change: partner(simIdP{Name: simPartnerName, Zone: "office"}, onAdmin(throughPartner))},
			{Name: "a partner provider that created it", Change: partner(simIdP{Name: simPartnerName}, onAdmin(func(a *roster.Account) {
				throughPartner(a)
				simulate.SetExtra(&a.Extra, "provider", "FEDERATION")
				simulate.SetExtra(&a.Extra, "routed", false)
			}))},
			{Name: "okta, with a partner provider for another domain", Change: partner(simIdP{Name: simPartnerName, Domains: []string{"partner.example"}})},
		}},
		{Name: "enroll", Values: []roster.Value{
			{Name: "challenge"},
			{Name: "at sign-in for everyone else", Change: setEnroll("default", "default", "LOGIN")},
			{Name: "at sign-in for the password-only group", Change: setEnroll("password_only", "never", "LOGIN")},
		}},
	}
}

// simMatrixStanding adds the app differences, which no axis changes, to
// the standing ones.
var simMatrixStanding = simStanding.With(simApps)

// simMatrixAlone lists, by setting, the values the collector reports
// otherwise when that setting alone changes.
var simMatrixAlone = map[string]simulate.Differences{
	"admin.state=staged": simStagedSuspended,
}

func TestSimulatedMatrix(t *testing.T) {
	simHarness(t, simMatrixStanding).Matrix(t, simMatrixBase(t), simMatrixAxes(), simMatrixAlone, nil)
}

// simMFAPointers are the values roster.Derive leaves out when an account
// signs in through another identity provider: the first seven when a user
// does, the rest when an admin does.
var simMFAPointers = []string{
	"/user_security/mfa_user_count", "/user_security/phishing_resistant_user_count",
	"/user_security/mfa_coverage_pct", "/user_security/mfa_phishing_resistant_pct",
	"/policy/mfa_required", "/policy/mfa_required_user_count", "/policy/mfa_required_coverage_pct",
	"/privileged_access/privileged_mfa_user_count", "/privileged_access/privileged_phishing_resistant_user_count",
	"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_phishing_resistant_pct",
}

// TestSimulatedSignInElsewhere checks what the matrix can't: that the
// collector leaves out each MFA value Derive leaves out, for an account
// that signs in through another identity provider. In the scenarios and the
// one-at-a-time admin.signs_in rows, its gap names the provider. In a
// pairwise row another gap can say why first.
func TestSimulatedSignInElsewhere(t *testing.T) {
	type check struct {
		sc    simulate.Scenario
		named bool
	}
	var checks []check
	for _, sc := range simScenarios(t) {
		if strings.Contains(sc.Name, "identity provider") || strings.Contains(sc.Name, "routing rule") {
			checks = append(checks, check{sc, true})
		}
	}
	h, base, axes := simHarness(t, simMatrixStanding), simMatrixBase(t), simMatrixAxes()
	for _, set := range []struct {
		rows  []roster.Row
		named bool
	}{{roster.OneAtATime(axes), true}, {roster.Pairwise(axes), false}} {
		for _, row := range set.rows {
			if !slices.ContainsFunc(row.Choices(axes), func(c string) bool { return strings.HasPrefix(c, "admin.signs_in=") }) {
				continue
			}
			v, err := roster.Build(base, axes, row)
			if err != nil {
				t.Fatal(err)
			}
			checks = append(checks, check{simulate.Scenario{Name: v.Name, Roster: v.Roster}, set.named})
		}
	}
	for _, c := range checks {
		t.Run(c.sc.Name, func(t *testing.T) {
			derived, err := roster.Derive(c.sc.Roster)
			if err != nil {
				t.Fatal(err)
			}
			res := h.Collect(t, h.Simulate(c.sc.Roster, 0))
			var doc map[string]any
			for _, a := range res.Artifacts {
				if a.Path == idpPosturePath {
					if err := json.Unmarshal(a.Data, &doc); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, pointer := range simMFAPointers {
				if _, want := derived[roster.IDPPosture][pointer]; want {
					continue
				}
				i := slices.IndexFunc(res.Result.Gaps, func(g componentsdk.Gap) bool { return g.Path == idpPosturePath && g.Pointer == pointer })
				switch _, got := simLookup(doc, pointer); {
				case got:
					t.Errorf("%s: left out by Derive, collector wrote it", pointer)
				case i < 0:
					t.Errorf("%s: left out with no gap", pointer)
				case c.named && !strings.Contains(res.Result.Gaps[i].Detail, simPartnerName):
					t.Errorf("%s: left out with a gap that doesn't name %s: %s", pointer, simPartnerName, res.Result.Gaps[i].Detail)
				}
			}
		})
	}
}

// simLookup reads the value at a JSON pointer of doc.
func simLookup(doc map[string]any, pointer string) (any, bool) {
	var at any = doc
	for _, key := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		m, ok := at.(map[string]any)
		if !ok {
			return nil, false
		}
		if at, ok = m[key]; !ok || at == nil {
			return nil, false
		}
	}
	return at, true
}

// simRules hold whatever the right values are, so they run on random
// rosters from the matrix's axes, and a broken one is a bug with no verdict
// to settle.
var simRules = []simulate.Rule{
	{
		Name: "reordering accounts, groups and policies, and pages of two, change nothing",
		Change: func(r *roster.Roster, rng *rand.Rand) int {
			rng.Shuffle(len(r.Accounts), func(i, j int) { r.Accounts[i], r.Accounts[j] = r.Accounts[j], r.Accounts[i] })
			rng.Shuffle(len(r.Groups), func(i, j int) { r.Groups[i], r.Groups[j] = r.Groups[j], r.Groups[i] })
			rng.Shuffle(len(r.Policies), func(i, j int) { r.Policies[i], r.Policies[j] = r.Policies[j], r.Policies[i] })
			return 2
		},
		Check: func(before, after map[string]any) []string { return simulate.Unchanged(before, after, nil) },
	},
	{
		Name: "another factor never lowers an MFA value",
		Change: func(r *roster.Roster, rng *rand.Rand) int {
			a := &r.Accounts[rng.IntN(len(r.Accounts))]
			a.Methods = append(slices.Clone(a.Methods), "webauthn")
			return 0
		},
		Check: func(before, after map[string]any) []string {
			return simulate.NeverLower(before, after, "idp-posture:/user_security/mfa_user_count", "idp-posture:/user_security/phishing_resistant_user_count",
				"idp-posture:/privileged_access/privileged_mfa_user_count", "idp-posture:/privileged_access/privileged_phishing_resistant_user_count")
		},
	},
	{
		Name: "narrowing a rule that requires MFA never raises the coverage",
		Change: func(r *roster.Roster, rng *rand.Rand) int {
			var mfa []int
			for i, p := range r.Policies {
				if len(p.Requires) > 0 {
					mfa = append(mfa, i)
				}
			}
			if len(mfa) > 0 {
				p := &r.Policies[mfa[rng.IntN(len(mfa))]]
				p.Conditions = append(slices.Clone(p.Conditions), "risk_high")
			}
			return 0
		},
		Check: func(before, after map[string]any) []string {
			broken := simulate.NeverHigher(before, after, "idp-posture:/policy/mfa_required_user_count")
			if before["idp-posture:/policy/mfa_required"] == false && after["idp-posture:/policy/mfa_required"] == true {
				broken = append(broken, "/policy/mfa_required went from false to true")
			}
			return broken
		},
	},
}

func TestSimulatedRules(t *testing.T) {
	simHarness(t, simMatrixStanding).Rules(t, simMatrixBase(t), simMatrixAxes(), simRules, 20, 20261111)
}

package collector

import (
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated orgs are rosters the Okta simulator answers for, each with
// the idp-posture values roster.Derive computes from it. A value the
// collector reports otherwise is listed with a verdict and a note that says
// where in the collector's code it was checked, so a new difference fails,
// and so does a listed one that goes away.

// simRoster is the sandbox's roster in v1 form, which cmd/derive in
// epack-collector-sandboxes converts from sandboxes/okta/roster.json.
const simRoster = "testdata/simulator/okta.roster.json"

// simConfig runs the collector at the audit level, the sandbox's and its
// recording's, as the service app.
func simConfig() map[string]any {
	config := kitOAuthConfig()
	config["level"] = "audit"
	return config
}

// simHarness runs the collector against the simulated org and checks each
// answer's shape against the sandbox's recording.
func simHarness(t testing.TB, standing simulate.Differences) simulate.Harness {
	rec := simRecording(t)
	return simulate.Harness{
		Simulate: func(r *roster.Roster, pageSize int) []collectortest.Response {
			return newOktaSim(r, rec, kitNow, pageSize).responses()
		},
		Collect: func(t *testing.T, responses []collectortest.Response) componentsdk.InProcessResult {
			return simulate.InProcess(t, Spec("test", "simulator"), Run, componentsdk.InProcessOptions{
				Config:  simConfig(),
				Secrets: map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()},
				Clock:   func() time.Time { return kitNow },
			}, responses)
		},
		Artifacts:  []simulate.Artifact{{Schema: roster.IDPPosture, Path: idpPosturePath}},
		Standing:   standing,
		Recorded:   rec,
		Unrecorded: simUnrecorded,
		Coverage:   true,
		Uncompared: map[string]string{
			"/privileged_access/privileged_users_present": "roster.Derive in epack v0.11.1 gives it only with the admins' MFA percentages, which it leaves out when an admin signs in through another identity provider",
		},
	}
}

// simUnrecorded lists the answers the sandbox's recording can't vouch for,
// with why. Each comes from a setting the scenarios or the matrix invent
// that the sandbox doesn't have.
var simUnrecorded = map[string]string{
	"okta.api_tokens.list: unrecorded status 403":                                     "the sandbox's collector app is a Super Administrator, so nothing refuses it; the body is the kit's E0000006 refusal",
	"okta.iam.assignees.list: unrecorded status 403":                                  "the sandbox's collector app is a Super Administrator, so nothing refuses it; the body is the kit's E0000006 refusal",
	"okta.apps.list []._links.accessPolicy: missing field":                            "the sandbox is an Identity Engine org, where every app has an app sign-in policy; the scenario and the matrix with none stand for a Classic Engine org",
	"okta.iam.roles.permissions.list: unrecorded operation":                           "the sandbox has no custom admin role, and the collector skips the permissions of Okta's Workflows Administrator",
	"okta.users.roles.list [].role: unrecorded field":                                 "the sandbox has no custom admin role, whose assignment names the role's ID in role",
	"okta.policies.rules.list [].conditions.device: unrecorded field":                 "Identity Engine global session rules have no device condition; the matrix's managed-device rule stands for a Classic Engine sign-on rule",
	"okta.policies.rules.list [].conditions.people.groups: unrecorded field":          "the sandbox's sign-on rules exclude no group",
	"okta.policies.rules.list [].conditions.people.users.exclude[]: unrecorded field": "the sandbox's sign-on rules exclude no user, so the recording holds only empty lists",
	"okta.iam.assignees.list _links: unrecorded field":                                "the sandbox's admins fit one page, so the recording holds no next page's link, which Okta's API reference puts in _links.next.href",
	"okta.iam.roles.list _links.next: unrecorded field":                               "the sandbox's roles fit one page, so the recording holds no next page's link, which Okta's API reference puts in _links.next.href",
	"okta.policies.list [].conditions: type":                                          simRoutingUnrecorded,
	"okta.policies.rules.list [].actions.idp: unrecorded field":                       simRoutingUnrecorded,
	"okta.policies.rules.list [].conditions.people: missing field":                    simRoutingUnrecorded + "; a routing rule has no people condition",
	"okta.policies.rules.list [].conditions.userIdentifier: unrecorded field":         simRoutingUnrecorded,
	"okta.policies.rules.list [].conditions.network.include: unrecorded field":        simRoutingUnrecorded + "; the sandbox's sign-on rules name no zone",
	"okta.idps.list []: unrecorded field":                                             "the sandbox has no identity provider; each follows the SAML 2.0 provider in Okta's API reference (SamlIdPResponse)",
}

// simRoutingUnrecorded is why the recording can't vouch for the IdP routing
// policy and its rules.
const simRoutingUnrecorded = "the recording was made by a collector that didn't read the IdP routing policy, so its shape follows Okta's API reference (IdpDiscoveryPolicyRule) and its examples"

// simStanding are differences that hold wherever the collector reads the
// value.
var simStanding = simulate.Same(simulate.Gap, "not_read: normalized.go idpPostureLeftOut, since Okta sets which clients may sign in to an app in its app sign-in policy, which the collector does not read", "/policy/legacy_auth_blocked").With(
	simulate.Same(simulate.Gap, "not_read: idpPostureLeftOut, since app sign-in policy rules are not read", "/policy/phishing_resistant_required_for_privileged"),
	simulate.Same(simulate.Gap, "not_read: idpPostureLeftOut, since Okta's user grants API, which the collector does not read, reports the apps users have granted access to",
		"/app_security/authorized_third_party_apps_count"),
	simulate.Same(simulate.Gap, "unsupported: idpPostureLeftOut, since Okta does not report how strong a user's password is",
		"/user_security/weak_password_user_count", "/user_security/weak_password_pct"),
	simulate.Same(simulate.Gap, "unsupported: idpPostureLeftOut, since Okta does not report whether a user's password meets the password policy",
		"/user_security/password_policy_noncompliant_user_count", "/user_security/password_policy_noncompliant_pct"),
	simulate.Same(simulate.Definition, "Okta's DEPROVISIONED status fits the schema's archived state, and Okta lists those users only when asked by filter; idpPostureLeftOut calls archived unsupported, since Okta has no state by that name",
		"/lifecycle/archived_account_count", "/lifecycle/archived_pct"),
)

var (
	simApps = simulate.Same(simulate.Known,
		"apps.go processApp leaves out Okta's Admin Console, Dashboard and Browser Plugin, which only a Super Admin sees, and client-credentials service apps, as the v0.5.0 changelog says",
		"/app_security/app_count", "/app_security/sso_app_count", "/app_security/sso_coverage_pct",
		"/app_security/provisioning_enabled_pct", "/app_security/deprovisioning_enabled_pct")
	simStagedSuspended = simulate.Same(simulate.Unmodeled,
		"roster v1 has one enabled flag, so a staged user, never activated, counts as suspended or disabled",
		"/lifecycle/suspended_account_count", "/lifecycle/suspended_pct")
	simMFARequirement    = []string{"/policy/mfa_required", "/policy/mfa_required_coverage_pct", "/policy/mfa_required_user_count"}
	simAppSignInPolicies = simulate.Same(simulate.Gap,
		"not_read: normalized.go markMFARequirementUnread, since the sandbox's apps have app sign-in policies, which the collector does not read",
		simMFARequirement...)
	simBaseline = simApps.With(simStagedSuspended, simAppSignInPolicies)
)

func simBase(t testing.TB) *roster.Roster {
	t.Helper()
	r, err := roster.Load(simRoster)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func validated(t testing.TB, r *roster.Roster) *roster.Roster {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

func simScenarios(t testing.TB) []simulate.Scenario {
	t.Helper()
	base := simBase(t)
	out := simulate.Realizations(t, "baseline", base, simBaseline)
	reals, err := base.Realizations()
	if err != nil {
		t.Fatal(err)
	}
	first := reals[0].Roster
	classic := withoutAppSignInPolicies(first)
	out = append(out,
		simulate.Scenario{
			Name: "no app sign-in policies", Roster: validated(t, classic),
			// The collector writes the MFA requirement now.
			Differences: simApps.With(simStagedSuspended),
		},
		simulate.Scenario{
			Name: "1000 users", Roster: validated(t, manyUsers(first, 1000)),
			// One staged user among a thousand doesn't move the rounded share.
			Differences: simBaseline.Without("/lifecycle/suspended_pct"),
		},
		simulate.Scenario{
			Name: "deprovisioned user", Roster: validated(t, withDeprovisioned(first)),
			Differences: simBaseline.With(
				simulate.Same(simulate.Definition, "Okta lists DEPROVISIONED users only when asked by filter, and users.go reads the plain list, so a deactivated user, which fits the schema's archived or soft-deleted state, is in no lifecycle count; idpPostureLeftOut calls archived unsupported",
					"/lifecycle/account_count")),
		},
		simulate.Scenario{
			Name: "collector app is a Read-Only Administrator", Roster: validated(t, readOnlyCollector(first)),
			Differences: simBaseline.With(
				simulate.Same(simulate.Gap, "permission_denied: privileged.go, since listing role assignees takes a Super Administrator",
					"/privileged_access/privileged_users_count", "/privileged_access/standing_privileged_users_count", "/privileged_access/super_admin_count",
					"/privileged_access/privileged_mfa_coverage_pct", "/privileged_access/privileged_mfa_user_count",
					"/privileged_access/privileged_phishing_resistant_pct", "/privileged_access/privileged_phishing_resistant_user_count",
					"/privileged_access/privileged_users_present", "/privileged_access/standing_privileged_users_present",
					"/device_access/managed_device_required_for_admins")),
		},
		simulate.Scenario{Name: "super admin through a group", Roster: validated(t, groupSuperAdmin(first)), Differences: simBaseline},
		simulate.Scenario{Name: "custom admin role", Roster: validated(t, customAdmin(first)), Differences: simBaseline},
		simulate.Scenario{
			Name:        "a member signs in through another identity provider",
			Roster:      validated(t, elsewhere(classic, simIdP{Name: simPartnerName}, simulate.OnAccount("user_email", throughPartner))),
			Differences: simApps.With(simStagedSuspended),
		},
		simulate.Scenario{
			Name:        "an admin signs in through another identity provider",
			Roster:      validated(t, elsewhere(first, simIdP{Name: simPartnerName}, simulate.OnAccount("admin_totp", throughPartner))),
			Differences: simBaseline,
		},
		simulate.Scenario{
			Name: "a member an identity provider created, with no routing rule",
			Roster: validated(t, elsewhere(classic, simIdP{Name: simPartnerName}, simulate.OnAccount("user_otp", func(a *roster.Account) {
				throughPartner(a)
				simulate.SetExtra(&a.Extra, "provider", "FEDERATION")
				simulate.SetExtra(&a.Extra, "routed", false)
			}))),
			Differences: simApps.With(simStagedSuspended),
		},
		simulate.Scenario{
			Name:        "a routing rule no account matches",
			Roster:      validated(t, elsewhere(classic, simIdP{Name: simPartnerName, Domains: []string{"partner.example"}})),
			Differences: simApps.With(simStagedSuspended),
		},
	)
	return out
}

// simPartner is the identity provider the sign-in variants send accounts
// to, and simPartnerName its name in Okta.
const (
	simPartner     = "partner"
	simPartnerName = "Partner SAML"
)

// elsewhere gives a copy of base the partner identity provider, then makes
// the changes.
func elsewhere(base *roster.Roster, idp simIdP, changes ...func(*roster.Roster)) *roster.Roster {
	r := base.Clone()
	simulate.SetExtra(&r.Extra, "identity_providers", map[string]simIdP{simPartner: idp})
	for _, change := range changes {
		change(r)
	}
	return r
}

// throughPartner has an account sign in through the partner identity
// provider, with a login at its domain.
func throughPartner(a *roster.Account) {
	a.SignsInThrough = simPartner
	simulate.SetExtra(&a.Extra, "login", strings.ReplaceAll(a.Key, "_", ".")+"@partner.example")
}

// withoutAppSignInPolicies is the sandbox with no app sign-in policy on any
// app, as in an org on the Classic Engine.
func withoutAppSignInPolicies(base *roster.Roster) *roster.Roster {
	r := base.Clone()
	for i := range r.Apps {
		simulate.SetExtra(&r.Apps[i].Extra, "access_policy", false)
	}
	return r
}

// manyUsers adds members and admins to the sandbox until it has n
// accounts, in a fixed mix: a seventeenth suspended, sign-ins on either
// side of 90 days, some in each sandbox group, and some admins.
func manyUsers(base *roster.Roster, n int) *roster.Roster {
	r := base.Clone()
	signIns := []*int{intPtr(0), intPtr(30), intPtr(89), intPtr(91), intPtr(400), nil}
	groups := map[string]int{}
	for i, g := range r.Groups {
		groups[g.Key] = i
	}
	for i := len(r.Accounts); i < n; i++ {
		a := roster.Account{Key: fmt.Sprintf("user_%04d", i), Kind: "member", Enabled: i%17 != 0, SignedInDaysAgo: signIns[i%len(signIns)]}
		if !a.Enabled {
			a.State = StatusSuspended
		}
		switch i % 5 {
		case 1:
			a.Methods = []string{"token:software:totp"}
		case 2:
			a.Methods = []string{"email"}
		case 3:
			a.Methods = []string{"webauthn", "email"}
		}
		switch {
		case i%1000 == 0:
			a.Roles = []string{"SUPER_ADMIN"}
		case i%250 == 0:
			a.Roles = []string{"ORG_ADMIN"}
		}
		switch i % 3 {
		case 1:
			g := &r.Groups[groups["mfa_required"]]
			g.Members = append(g.Members, a.Key)
		case 2:
			g := &r.Groups[groups["password_only"]]
			g.Members = append(g.Members, a.Key)
		}
		r.Accounts = append(r.Accounts, a)
	}
	return r
}

// withDeprovisioned adds a deactivated user, whom Okta lists only by filter.
func withDeprovisioned(base *roster.Roster) *roster.Roster {
	r := base.Clone()
	a := roster.Account{Key: "user_deprovisioned", Kind: "member", Methods: []string{"email"}, SignedInDaysAgo: intPtr(200)}
	a.State = StatusDeprovisioned
	r.Accounts = append(r.Accounts, a)
	return r
}

// readOnlyCollector gives the collector's service app Read-Only
// Administrator in place of Super Administrator.
func readOnlyCollector(base *roster.Roster) *roster.Roster {
	r := base.Clone()
	simulate.OnApp("collector", func(a *roster.App) { simulate.SetExtra(&a.Extra, "roles", []string{"READ_ONLY_ADMIN"}) })(r)
	return r
}

// groupSuperAdmin gives Super Administrator to a group holding user.otp.
func groupSuperAdmin(base *roster.Roster) *roster.Roster {
	r := base.Clone()
	r.Groups = append(r.Groups, roster.Group{Key: "super_admins", Members: []string{"user_otp"}, Roles: []string{"SUPER_ADMIN"}})
	return r
}

// customAdmin gives user.otp a custom role that can manage users.
func customAdmin(base *roster.Roster) *roster.Roster {
	r := base.Clone()
	r.Terms.Roles = maps.Clone(r.Terms.Roles)
	r.Terms.Roles["User Manager"] = roster.RoleAdmin
	simulate.SetExtra(&r.Extra, "custom_roles", map[string]any{"User Manager": map[string]any{"permissions": []string{"okta.users.read", "okta.users.manage"}}})
	simulate.OnAccount("user_otp", func(a *roster.Account) { a.Roles = []string{"User Manager"} })(r)
	return r
}

func TestSimulatedOrgs(t *testing.T) {
	simHarness(t, simStanding).Tenants(t, simScenarios(t))
}

// TestSimulatedShapes checks the answers for every scenario and every
// one-at-a-time matrix row against the recording, and that each
// simUnrecorded listing is still needed.
func TestSimulatedShapes(t *testing.T) {
	var rosters []*roster.Roster
	for _, sc := range simScenarios(t) {
		rosters = append(rosters, sc.Roster)
	}
	axes := simMatrixAxes()
	for _, row := range roster.OneAtATime(axes) {
		v, err := roster.Build(simMatrixBase(t), axes, row)
		if err != nil {
			t.Fatal(err)
		}
		rosters = append(rosters, v.Roster)
	}
	simHarness(t, simStanding).CheckRecorded(t, rosters...)
}

// TestSimulatedOrgsKit runs the kit's checks over the simulated orgs: the
// fault matrix and the rest on the first baseline, and each scenario's
// derived values, less the listed differences, as Expect.
func TestSimulatedOrgsKit(t *testing.T) {
	h := simHarness(t, simStanding)
	var scenarios []collectortest.Scenario
	for _, sc := range simScenarios(t) {
		scenarios = append(scenarios, collectortest.Scenario{
			Name:      sc.Name,
			Responses: h.Simulate(sc.Roster, 0),
			Expect:    h.Expect(t, sc),
		})
	}
	collectortest.Run(t, collectortest.Suite{
		Name:       "okta-simulated",
		Spec:       Spec("test", "collectortest"),
		Run:        Run,
		Config:     simConfig(),
		Secrets:    map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()},
		Clock:      kitNow,
		Scenarios:  scenarios,
		Required:   []string{"okta.token.create"},
		Semantics:  kitSemantics,
		Ignore:     kitIgnore,
		Operations: append([]string{"okta.token.create"}, simAuditOperations()...),
		// The baseline has no custom admin roles, so the custom role list
		// changes nothing there. The custom admin role scenario reads one.
		// At the audit level the collector reads only strings from the org,
		// which the sensitivity check doesn't change.
		Insensitive:   []string{"okta.token.create", "okta.iam.roles.list", "okta.org.get"},
		GapOperations: true,
		// Okta's IDs are 20 characters, so a failed per-user call's path in
		// a gap's detail, such as /api/v1/users/<id>/roles, is a run of 40
		// that redaction hides, in a real run too.
		SkipChecks: []string{"redaction"},
	})
}

// simAuditOperations are the calls a run at the audit level makes. The
// users' groups and the org's contacts are read at the internal level only.
func simAuditOperations() []string {
	return slices.DeleteFunc(slices.Clone(kitSurfaceOperations), func(op string) bool {
		return op == "okta.users.groups.list" || op == "okta.org.contacts.get"
	})
}

// simRecordingVocabulary are the fields whose spelling the simulator takes
// from Okta's documentation: statuses, types, modes, and the values the
// collector compares against.
var simRecordingVocabulary = []string{
	"[].status", "[].factorType", "[].provider", "[].type", "[].signOnMode", "[].assignmentType", "[].key",
	"[].actions.signon.access", "[].actions.signon.primaryFactor", "[].actions.signon.factorPromptMode", "[].actions.enroll.self",
	"[].conditions.network.connection", "[].conditions.authContext.authType", "[].conditions.riskScore.level",
	"[].settings.oauthClient.grant_types[]", "[].usage", "[].features[]", "[].profile.userType", "error.errorCode",
}

func TestSimulatorMatchesRecording(t *testing.T) {
	simulate.CheckRecording(t, simulate.Recording{
		Path: simRecordingPath,
		Env:  "OKTA_SIM_RECORDING",
		Options: collectortest.CompareOptions{
			Vocabulary: simRecordingVocabulary,
		},
		Rewrite: simRewriteIDs,
		Known:   simRecordingKnown,
		Simulate: func(t *testing.T, recordedAt time.Time) []collectortest.Response {
			reals, err := simBase(t).Realizations()
			if err != nil {
				t.Fatal(err)
			}
			return newOktaSim(reals[0].Roster, simRecording(t), recordedAt, 0).responses()
		},
	})
}

// simRecordingKnown lists the ways the simulator is known to differ from
// the recording, with why each is left.
var simRecordingKnown = map[string]string{
	"GET acme.okta.com/api/v1/logs?limit=200&since=2026-10-13T01:27:15Z&sortOrder=DESCENDING []: missing (recorded object, simulated nothing)": "the simulator's System Log holds no events",
	"GET acme.okta.com/api/v1/users/{id}/factors [].profile.authenticatorName: type (recorded null or string, simulated string)":               "each simulated WebAuthn factor copies the first recorded one, whose authenticator has a name; the roster doesn't say which keys have none",
	"GET acme.okta.com/api/v1/groups/{id}/users?limit=200: count (recorded 19, simulated 21)":                                                  "the recording reads the members of the three groups policies name; the simulator answers for every group, and the ID rewrite joins them",
	"GET acme.okta.com/api/v1/users/{id}/roles: count (recorded 3, simulated 4)":                                                               "the collector skips the roles of an admin whose account isn't enabled, the suspended one here; the simulator answers for every assignee, and the ID rewrite joins them",
	"GET acme.okta.com/api/v1/logs?limit=200&since=2026-10-13T01:27:15Z&sortOrder=DESCENDING: count (recorded 200, simulated 0)":               "the simulator's System Log holds no events",
	"GET acme.okta.com/api/v1/policies/{id}/rules: count (recorded 9, simulated 10)":                                                           simRoutingUnrecorded + "; the ID rewrite joins the routing policy's Default Rule to the other policies' rules",
	"GET acme.okta.com/api/v1/policies/{id}/rules [].actions.idp: extra (recorded nothing, simulated object)":                                  simRoutingUnrecorded,
	"GET acme.okta.com/api/v1/policies/{id}/rules [].type: values (recorded nothing, simulated IDP_DISCOVERY)":                                 simRoutingUnrecorded,
}

// simObjectID is an Okta object ID in a URL's path: a user, group, policy,
// app, or custom role.
var simObjectID = regexp.MustCompile(`/(?:00u|00g|00p|0oa|cr0)[0-9A-Za-z]{17}\b`)

// simRewriteIDs replaces the object IDs in a URL's path, which differ
// between the sandbox and the simulator, so per-object calls line up. It
// drops the System Log filter, since the recording was made with an older
// one, which kitRefilterRecordedSystemLog points at the current one.
func simRewriteIDs(u string) string {
	u = simObjectID.ReplaceAllString(u, "/{id}")
	parsed, err := url.Parse(u)
	if err != nil || parsed.Path != "/api/v1/logs" {
		return u
	}
	q := parsed.Query()
	q.Del("filter")
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

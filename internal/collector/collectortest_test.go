package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitSurfaceOperations are the calls both sign-in modes make after signing
// in.
var kitSurfaceOperations = []string{
	"okta.users.list",
	"okta.users.factors.list",
	"okta.users.groups.list",
	"okta.users.roles.list",
	"okta.iam.assignees.list",
	"okta.iam.roles.list",
	"okta.iam.roles.permissions.list",
	"okta.apps.list",
	"okta.policies.list",
	"okta.policies.rules.list",
	"okta.groups.list",
	"okta.groups.users.list",
	"okta.device_assurances.list",
	"okta.authenticators.list",
	"okta.zones.list",
	"okta.idps.list",
	"okta.api_tokens.list",
	"okta.event_hooks.list",
	"okta.inline_hooks.list",
	"okta.logs.list",
	"okta.org.get",
	"okta.org.contacts.get",
}

// kitSemantics are the statuses that are answers rather than failures.
var kitSemantics = []collectortest.Semantic{{
	Operation: "okta.iam.roles.list",
	Fault:     "404",
	Meaning:   "Okta Identity Governance is not licensed, so the org has no custom admin roles",
	Expect:    map[string]map[string]any{detailedPath: {"/privileged_access/custom_roles": nil}},
}}

// kitIgnore keeps the diagnostics warnings readers parse out of the value
// comparison: a fault adds a warning by design.
var kitIgnore = map[string][]string{detailedPath: {"/diagnostics"}}

// kitResultPath is where the kit's runs write their collector result.
const kitResultPath = "artifacts/okta.collector-result.json"

// kitSteps are a run's steps in order, with their titles. Runs below audit
// make only the first six.
var kitSteps = [][2]string{
	{"sign_in", "Sign in"},
	{"people", "People and sign-in methods"},
	{"apps", "Apps"},
	{"admin_roles", "Admin roles"},
	{"policies", "Sign-on and MFA policies"},
	{"device_assurance", "Device assurance"},
	{"authenticators", "Authenticators"},
	{"groups", "Groups"},
	{"network_zones", "Network zones"},
	{"identity_providers", "Identity providers"},
	{"api_tokens", "API tokens"},
	{"hooks", "Event and inline hooks"},
	{"system_log", "Activity log"},
	{"org_settings", "Org settings"},
}

// kitPins collects the values a scenario pins in the detailed artifact and
// in the collector result.
type kitPins struct{ detailed, result map[string]any }

func newKitPins() kitPins {
	return kitPins{detailed: map[string]any{}, result: map[string]any{}}
}

func (p kitPins) expect() map[string]map[string]any {
	return map[string]map[string]any{detailedPath: p.detailed, kitResultPath: p.result}
}

// kitOAuthName is the OAuth suite's configured name. Each suite needs its
// own, since the name also keys the suite's output under COLLECTORTEST_OUT.
const kitOAuthName = "okta-oauth"

// steps pins the 14 steps in order, and that there are no more.
func (p kitPins) steps() kitPins {
	for i, s := range kitSteps {
		p.result[fmt.Sprintf("/steps/%d/name", i)] = s[0]
		p.result[fmt.Sprintf("/steps/%d/title", i)] = s[1]
	}
	p.result[fmt.Sprintf("/steps/%d", len(kitSteps))] = collectortest.Absent
	return p
}

// tokenSignIn pins an API token sign-in, which asks for no scopes and makes
// no read-only claim, since the token acts with its owner's admin roles.
func (p kitPins) tokenSignIn() kitPins {
	p.result["/signed_in_as/auth_method"] = componentsdk.AuthAPIToken
	p.result["/signed_in_as/requested_scopes"] = collectortest.Absent
	p.result["/signed_in_as/read_only"] = collectortest.Absent
	return p
}

// appSignIn pins a service app sign-in that asked for requested and was
// granted granted, all of them read scopes.
func (p kitPins) appSignIn(requested, granted []string) kitPins {
	p.result["/signed_in_as/auth_method"] = componentsdk.AuthPrivateKeyJWT
	p.result["/signed_in_as/requested_scopes"] = sorted(requested)
	p.result["/signed_in_as/scopes"] = sorted(granted)
	p.result["/signed_in_as/read_only"] = true
	return p
}

// row pins fields of the request row at index.
func (p kitPins) row(index int, fields map[string]any) kitPins {
	for field, value := range fields {
		p.result[fmt.Sprintf("/calls/requests/%d/%s", index, field)] = value
	}
	return p
}

// noFailedReads pins the run's gaps to the normalized values the collector
// leaves out every time, one for each at the audit level and above.
func (p kitPins) noFailedReads() kitPins {
	for i, u := range idpPostureLeftOut {
		p.result[fmt.Sprintf("/gaps/%d/pointer", i)] = u.pointer
	}
	p.result[fmt.Sprintf("/gaps/%d", len(idpPostureLeftOut))] = collectortest.Absent
	return p
}

// onlyGap pins the run's one gap on the detailed artifact, which sorts
// first. The gaps on the normalized values the collector leaves out follow,
// one for each at the audit level and above.
func (p kitPins) onlyGap(gap map[string]any) kitPins {
	p.result["/gaps/0"] = gap
	for i, u := range idpPostureLeftOut {
		p.result[fmt.Sprintf("/gaps/%d/code", i+1)] = string(u.code)
		p.result[fmt.Sprintf("/gaps/%d/pointer", i+1)] = u.pointer
	}
	p.result[fmt.Sprintf("/gaps/%d", len(idpPostureLeftOut)+1)] = collectortest.Absent
	return p
}

func sorted(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}

// kitOAuthGap is gap as the OAuth suite's runs record it, with the path its
// configured name gives the detailed artifact.
func kitOAuthGap(gap map[string]any) map[string]any {
	gap["path"] = componentsdk.RunPath("okta", kitOAuthName, detailedPath)
	return gap
}

// kitRefusedLogGap is the gap a refused system log read leaves at the audit
// level and above, recorded in collectSystemLog.
func kitRefusedLogGap(call int, missing, warning string) map[string]any {
	gap := map[string]any{
		"path": detailedPath, "pointer": "/system_log", "status": "not_collected",
		"code": "permission_denied", "owner": "customer", "vendor_code": "E0000006",
		"operation": "okta.logs.list", "call": call,
		"source":  "internal/collector/system_log.go:154",
		"warning": warning,
		"detail":  "okta API /api/v1/logs returned status 403: E0000006 You do not have permission to perform the requested action",
	}
	if missing != "" {
		gap["missing_permission"] = missing
	}
	return gap
}

// kitLargeOrgScenario is the canvas's sample run at the audit level: three
// factor reads throttled once each, and the system log read refused, as the
// 1,243rd call, because the token lacks okta.logs.read.
func kitLargeOrgScenario() collectortest.Scenario {
	t := kitLargeOrg()
	granted := kitWithout(kitAuditScopes, "okta.logs.read")
	responses := []collectortest.Response{kitLogsRefused()}
	for _, i := range []int{206, 530, 865} {
		responses = append(responses, kitThrottled(kitBase+"/api/v1/users/"+t.users[i].ID+"/factors"))
	}
	responses = append(responses, kitOAuthResponsesGranting(t, granted)...)

	const factors = "okta.users.factors.list"
	throttled := func(call int) map[string]any {
		return map[string]any{"call": call, "operation": factors, "step": "people", "attempt": 1, "start_ms": 0, "status": 429, "vendor_code": "E0000047"}
	}
	retried := func(call int, waited int) map[string]any {
		return map[string]any{"call": call, "operation": factors, "step": "people", "attempt": 2, "start_ms": 0, "waited_ms": waited, "status": 200}
	}
	pins := newKitPins().appSignIn(kitAuditScopes, granted)
	// Three of the people with a factor are suspended, so 1,118 of the 1,189
	// with an enabled account have MFA.
	pins.detailed["/users/total_count"] = 1192
	pins.detailed["/users/enabled_count"] = 1189
	pins.detailed["/posture/mfa_enrolled_users_count"] = 1118
	pins.detailed["/posture/mfa_coverage"] = 94
	pins.detailed["/system_log"] = collectortest.Absent
	pins.result["/steps/1"] = map[string]any{
		"name": "people", "title": "People and sign-in methods", "start_ms": 0, "end_ms": 0,
		"requests": 1201, "calls": 1198, "retries": 3, "failed": 3, "any_failed": true,
		"operations": []any{map[string]any{"name": "okta.users.list", "calls": 6}, map[string]any{"name": factors, "calls": 1192}},
	}
	pins.result["/steps/12"] = map[string]any{
		"name": "system_log", "title": "Activity log", "start_ms": 0, "end_ms": 0,
		"requests": 1, "calls": 1, "retries": 0, "failed": 1, "any_failed": true,
		"operations": []any{map[string]any{"name": "okta.logs.list", "calls": 1}},
	}
	// Each retry waits for the rate limit to reset, a second, plus jitter.
	pins.row(213, throttled(214)).row(214, retried(214, 1052)).
		row(538, throttled(538)).row(539, retried(538, 1003)).
		row(874, throttled(873)).row(875, retried(873, 1068)).
		row(1000, map[string]any{"call": 1244, "operation": "okta.logs.list", "step": "system_log", "attempt": 1, "start_ms": 0, "status": 403, "vendor_code": "E0000006"})
	pins.result["/calls/requests/1001"] = collectortest.Absent
	pins.result["/calls/requests_dropped"] = 249
	pins.result["/calls/problem_requests_dropped"] = 0
	pins.onlyGap(kitOAuthGap(kitRefusedLogGap(1244, "okta.logs.read", "system log: access denied (403; grant okta.logs.read and an admin role that can read it)")))
	return collectortest.Scenario{
		Name:      "large org with throttled factor reads and a refused system log read",
		Config:    map[string]any{"level": "audit"},
		Responses: responses,
		Expect:    pins.expect(),
	}
}

func kitTokenConfig() map[string]any {
	return map[string]any{"org_domain": kitOrgDomain, "level": "internal"}
}

func kitOAuthConfig() map[string]any {
	return map[string]any{"org_domain": kitOrgDomain, "client_id": kitClientID, "key_id": kitKeyID, "level": "internal"}
}

// kitLaggedGroupStats is the clean tenant with Okta's statistics for the
// Admins group still counting a third member, as statistics can lag the
// live member list.
func kitLaggedGroupStats() *mockOktaClient {
	t := kitTenant()
	t.groups[0].Embedded = stats(3)
	return t
}

// kitPopulations are the lists in Okta's answers that are empty when there
// are none, each with its source.
var kitPopulations = []collectortest.Population{
	{Operation: "okta.apps.list", List: "/", Reason: "Only a Super Admin sees Okta's default apps, so another admin sees none in an org with no apps of its own: https://support.okta.com/help/s/article/Admin-user-unable-to-manage-default-Okta-Dashboard-Okta-Browser-Plugin-and-Okta-Admin-Console-applications"},
	{Operation: "okta.apps.list", List: "/*/features", Reason: "An app with no provisioning features lists none; the sandbox recording lists none for ten of its eleven apps."},
	{Operation: "okta.users.factors.list", List: "/", Reason: "A user who has enrolled no factor lists none; the sandbox recording lists none for five of its ten users."},
	{Operation: "okta.groups.users.list", List: "/", Reason: "A group can have no members; the sandbox recording's Okta Administrators group counts none."},
	{Operation: "okta.iam.roles.list", List: "/roles", Reason: "An org with no custom admin roles lists none, and custom_roles is then [], as docs/levels.md says."},
	{Operation: "okta.iam.roles.permissions.list", List: "/permissions", Reason: "A custom role with no permissions grants nothing, since Okta's custom roles \"limit an admin's access to a subset of permissions and resources\": https://developer.okta.com/docs/concepts/role-assignment/"},
	{Operation: "okta.policies.rules.list", List: "/", Reason: "\"Policies that have no rules aren't considered during evaluation and are never applied\": https://developer.okta.com/docs/concepts/policies/"},
	{Operation: "okta.device_assurances.list", List: "/", Reason: "An org with no device assurance policies lists none; the sandbox recording lists none."},
	{Operation: "okta.zones.list", List: "/*/gateways", Reason: "A zone with no gateways has none; the sandbox recording's system IP zones send them as null."},
	{Operation: "okta.idps.list", List: "/", Reason: "An org with no identity providers lists none; the sandbox recording lists none."},
	{Operation: "okta.event_hooks.list", List: "/", Reason: "An org with no event hooks lists none; the sandbox recording lists none."},
	{Operation: "okta.inline_hooks.list", List: "/", Reason: "An org with no inline hooks lists none; the sandbox recording lists none."},
	{Operation: "okta.logs.list", List: "/", Reason: "A week with none of the events the filter names lists none, and Okta can end the log with an empty page, as the v0.5.0 CHANGELOG says."},
}

// kitOAuthPopulations are kitPopulations for a service app, which signs in
// with no API token of its own.
var kitOAuthPopulations = slices.Concat(kitPopulations, []collectortest.Population{
	{Operation: "okta.api_tokens.list", List: "/", Reason: "An org with no API tokens lists none; the sandbox recording, read by a service app, lists none."},
})

// kitOmissions are the fields Okta leaves out, or sends as null, to mean a
// value, each with its source.
var kitOmissions = []collectortest.Omission{
	{Operation: "okta.users.list", Field: "/*/lastLogin", Reason: "User.lastLogin is nullable in Okta's Users API reference, and the sandbox recording sends null for users who never signed in."},
	{Operation: "okta.policies.rules.list", Field: "/*/priority", Reason: "PolicyRule.priority is nullable in Okta's Policy API reference, and Okta evaluates a rule with no priority last, as the v0.5.2 CHANGELOG says."},
	{Operation: "okta.policies.rules.list", Field: "/*/conditions/device/managed", Reason: "A rule sends managed only when it limits sign-ins by it: \"When the managed property is passed, you must also include the registered property\" in Okta's Policy API reference."},
	{Operation: "okta.zones.list", Field: "/*/gateways", Reason: "A zone with no gateways sends them as null, or not at all for a DYNAMIC_V2 zone; the sandbox recording shows both."},
}

func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:        Spec("test", "collectortest"),
		Run:         Run,
		Config:      kitTokenConfig(),
		Secrets:     map[string]string{"OKTA_API_TOKEN": kitAPIToken},
		Clock:       kitNow,
		FieldFaults: true,
		Populations: kitPopulations,
		Omissions:   kitOmissions,
		Scenarios: []collectortest.Scenario{
			{Name: "clean", Responses: kitResponses(kitTenant()), Expect: newKitPins().steps().tokenSignIn().expect()},
			{
				Name:          "token rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{{
					URL:    kitBase + "/api/v1/users/me",
					Status: http.StatusUnauthorized,
					Body:   `{"errorCode":"E0000011","errorSummary":"Invalid token provided","errorLink":"E0000011","errorId":"oae-kit","errorCauses":[]}`,
				}},
			},
			{Name: "new org", Responses: kitResponses(kitNewOrg()), Expect: newKitPins().noFailedReads().expect()},
			{Name: "group statistics lag the member list", Responses: kitResponses(kitLaggedGroupStats())},
			{
				// An API token has no scopes, so the gap names none.
				Name:      "system log refused for the API token's owner",
				Responses: append([]collectortest.Response{kitLogsRefused()}, kitResponses(kitTenant())...),
				Expect: newKitPins().onlyGap(kitRefusedLogGap(43, "",
					"system log: access denied (403; the API token's owner needs an admin role that can read it)")).expect(),
			},
		},
		Required:      []string{"okta.users.me.get"},
		Semantics:     kitSemantics,
		Ignore:        kitIgnore,
		Operations:    append([]string{"okta.users.me.get"}, kitSurfaceOperations...),
		Insensitive:   []string{"okta.users.me.get"},
		GapOperations: true,
	})
}

func TestCollectorKitOAuth(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Name:        kitOAuthName,
		Spec:        Spec("test", "collectortest"),
		Run:         Run,
		Config:      kitOAuthConfig(),
		Secrets:     map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()},
		Clock:       kitNow,
		FieldFaults: true,
		Populations: kitOAuthPopulations,
		Omissions:   kitOmissions,
		Scenarios: append([]collectortest.Scenario{
			{
				Name:      "clean",
				Responses: kitOAuthResponses(kitTenant()),
				Expect: newKitPins().steps().appSignIn(kitAuditScopes, []string{
					"okta.users.read", "okta.groups.read", "okta.apps.read", "okta.policies.read", "okta.roles.read", "okta.deviceAssurance.read",
				}).expect(),
			},
			{
				Name:          "assertion rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{{
					Method: http.MethodPost,
					URL:    kitBase + "/oauth2/v1/token",
					Status: http.StatusUnauthorized,
					Body:   `{"error":"invalid_client","error_description":"The client_assertion signature is invalid."}`,
				}},
			},
			{
				Name:          "DPoP required",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{{
					Method: http.MethodPost,
					URL:    kitBase + "/oauth2/v1/token",
					Status: http.StatusBadRequest,
					Body:   `{"error":"invalid_dpop_proof","error_description":"The DPoP proof JWT header is missing."}`,
				}},
			},
			kitLargeOrgScenario(),
			{
				// The token carries okta.logs.read, so the refusal is the
				// service app's admin role, and the gap names no scope.
				Name:      "system log refused for the service app's admin role",
				Config:    map[string]any{"level": "audit"},
				Responses: append([]collectortest.Response{kitLogsRefused()}, kitOAuthResponsesGranting(kitTenant(), kitAuditScopes)...),
				Expect: newKitPins().appSignIn(kitAuditScopes, kitAuditScopes).onlyGap(kitOAuthGap(kitRefusedLogGap(34, "",
					"system log: access denied (403; okta.logs.read is granted, so the service app needs an admin role that can read it)"))).expect(),
			},
		}, kitRecordings(t, "okta")...),
		Required:      []string{"okta.token.create"},
		Semantics:     kitSemantics,
		Ignore:        kitIgnore,
		Operations:    append([]string{"okta.token.create"}, kitSurfaceOperations...),
		Insensitive:   []string{"okta.token.create"},
		GapOperations: true,
	})
}

// kitRecordings loads the scenarios TestRecord in record_test.go records
// from sandboxes, and logs each one not recorded yet.
func kitRecordings(t *testing.T, names ...string) []collectortest.Scenario {
	t.Helper()
	var out []collectortest.Scenario
	for _, name := range names {
		path := filepath.Join("testdata", "recordings", name+".json")
		sc, err := collectortest.LoadScenario(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			t.Logf("no recording at %s yet", path)
		case err != nil:
			t.Fatal(err)
		default:
			out = append(out, kitAnswerRecordedRouting(kitEndRecordedSystemLog(kitRefilterRecordedSystemLog(sc))))
		}
	}
	return out
}

// kitRefilterRecordedSystemLog points a recording's first System Log
// request at the current filter. The recording was made while the filter
// named four event types Okta does not have, in place of policy.rule.add and
// the zone events. Its answer holds no events of those two kinds. Record the
// sandbox again to replace it.
func kitRefilterRecordedSystemLog(sc collectortest.Scenario) collectortest.Scenario {
	for i, r := range sc.Responses {
		if r.Operation != "okta.logs.list" {
			continue
		}
		u, err := url.Parse(r.URL)
		if err != nil || u.Query().Get("after") != "" {
			continue
		}
		q := u.Query()
		q.Set("filter", buildSystemLogFilter())
		u.RawQuery = q.Encode()
		sc.Responses[i].URL = u.String()
	}
	return sc
}

// kitAnswerRecordedRouting answers the IdP routing policy list with an
// empty one when the recording has no answer for it. The recording was made
// before the collector read the routing rules. Record the sandbox again to
// replace it with Okta's answer.
func kitAnswerRecordedRouting(sc collectortest.Scenario) collectortest.Scenario {
	routing := kitBase + "/api/v1/policies?type=" + PolicyTypeIdPDiscovery
	if !slices.ContainsFunc(sc.Responses, func(r collectortest.Response) bool { return r.URL == routing }) {
		sc.Responses = append(sc.Responses, collectortest.Response{Operation: "okta.policies.list", URL: routing, Body: "[]"})
	}
	return sc
}

// kitEndRecordedSystemLog answers the System Log page that a recording's
// last System Log answer offers with an empty page. The recording was made
// when the collector read only the first page, so it holds no answer for
// the next one. Record the sandbox again to replace it with a recorded
// page.
func kitEndRecordedSystemLog(sc collectortest.Scenario) collectortest.Scenario {
	for i := len(sc.Responses) - 1; i >= 0; i-- {
		r := sc.Responses[i]
		if r.Operation != "okta.logs.list" {
			continue
		}
		resp := &http.Response{Header: r.Header}
		next, ok := componentsdk.NextLink(resp)
		if !ok {
			break
		}
		for _, answered := range sc.Responses {
			if answered.URL == next.String() {
				return sc
			}
		}
		sc.Responses = append(sc.Responses, collectortest.Response{Operation: "okta.logs.list", URL: next.String(), Body: "[]"})
		break
	}
	return sc
}

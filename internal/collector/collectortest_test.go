package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
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

// onlyGap pins the run's one gap.
func (p kitPins) onlyGap(gap map[string]any) kitPins {
	p.result["/gaps/0"] = gap
	p.result["/gaps/1"] = collectortest.Absent
	return p
}

func sorted(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
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
	pins.detailed["/users/total_count"] = 1192
	pins.detailed["/posture/mfa_enrolled_users_count"] = 1121
	pins.detailed["/posture/mfa_coverage"] = 94
	pins.detailed["/system_log"] = collectortest.Absent
	pins.result["/steps/1"] = map[string]any{
		"name": "people", "title": "People and sign-in methods", "start_ms": 0, "end_ms": 0,
		"requests": 1201, "calls": 1198, "retries": 3, "failed": 3,
		"operations": []any{map[string]any{"name": "okta.users.list", "calls": 6}, map[string]any{"name": factors, "calls": 1192}},
	}
	pins.result["/steps/12"] = map[string]any{
		"name": "system_log", "title": "Activity log", "start_ms": 0, "end_ms": 0,
		"requests": 1, "calls": 1, "retries": 0, "failed": 1,
		"operations": []any{map[string]any{"name": "okta.logs.list", "calls": 1}},
	}
	// Each retry waits for the rate limit to reset, a second, plus jitter.
	pins.row(213, throttled(214)).row(214, retried(214, 1052)).
		row(538, throttled(538)).row(539, retried(538, 1003)).
		row(874, throttled(873)).row(875, retried(873, 1068)).
		row(1000, map[string]any{"call": 1243, "operation": "okta.logs.list", "step": "system_log", "attempt": 1, "start_ms": 0, "status": 403, "vendor_code": "E0000006"})
	pins.result["/calls/requests/1001"] = collectortest.Absent
	pins.result["/calls/requests_dropped"] = 248
	pins.result["/calls/problem_requests_dropped"] = 0
	pins.onlyGap(kitRefusedLogGap(1243, "okta.logs.read", "system log: access denied (403; grant okta.logs.read and an admin role that can read it)"))
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

func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  kitTokenConfig(),
		Secrets: map[string]string{"OKTA_API_TOKEN": kitAPIToken},
		Clock:   kitNow,
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
			{Name: "empty tenant", Responses: kitResponses(kitEmptyTenant())},
			{Name: "group statistics lag the member list", Responses: kitResponses(kitLaggedGroupStats())},
			{
				// An API token has no scopes, so the gap names none.
				Name:      "system log refused for the API token's owner",
				Responses: append([]collectortest.Response{kitLogsRefused()}, kitResponses(kitTenant())...),
				Expect: newKitPins().onlyGap(kitRefusedLogGap(42, "",
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
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  kitOAuthConfig(),
		Secrets: map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()},
		Clock:   kitNow,
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
				Expect: newKitPins().appSignIn(kitAuditScopes, kitAuditScopes).onlyGap(kitRefusedLogGap(33, "",
					"system log: access denied (403; okta.logs.read is granted, so the service app needs an admin role that can read it)")).expect(),
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
			out = append(out, sc)
		}
	}
	return out
}

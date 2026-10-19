package collector

import (
	"errors"
	"io/fs"
	"net/http"
	"path/filepath"
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
	"okta.org.preferences.get",
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
			{Name: "clean", Responses: kitResponses(kitTenant())},
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
		},
		Required:    []string{"okta.users.me.get"},
		Semantics:   kitSemantics,
		Ignore:      kitIgnore,
		Operations:  append([]string{"okta.users.me.get"}, kitSurfaceOperations...),
		Insensitive: []string{"okta.users.me.get"},
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
			{Name: "clean", Responses: kitOAuthResponses(kitTenant())},
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
		}, kitRecordings(t, "okta")...),
		Required:    []string{"okta.token.create"},
		Semantics:   kitSemantics,
		Ignore:      kitIgnore,
		Operations:  append([]string{"okta.token.create"}, kitSurfaceOperations...),
		Insensitive: []string{"okta.token.create"},
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

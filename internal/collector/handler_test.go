package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestRunFailsOnInvalidConfiguration(t *testing.T) {
	cases := []struct {
		name    string
		config  map[string]any
		secrets map[string]string
	}{
		{"no org domain", map[string]any{"level": "trust"}, map[string]string{"OKTA_API_TOKEN": kitAPIToken}},
		{"no credentials", map[string]any{"org_domain": kitOrgDomain}, nil},
		{"service app without key_id", map[string]any{"org_domain": kitOrgDomain, "client_id": kitClientID}, map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()}},
		{"malformed private key", map[string]any{"org_domain": kitOrgDomain, "client_id": kitClientID, "key_id": kitKeyID}, map[string]string{"OKTA_PRIVATE_KEY": "not a key"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runInProcess(t, tc.config, tc.secrets, nil)
			if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
				t.Fatalf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
			}
		})
	}
}

func TestRunRecordsTheSignedInPrincipal(t *testing.T) {
	cases := []struct {
		name      string
		config    map[string]any
		secrets   map[string]string
		responses []collectortest.Response
		want      componentsdk.Principal
	}{
		{
			name: "api token", config: kitTokenConfig(), secrets: map[string]string{"OKTA_API_TOKEN": kitAPIToken},
			responses: kitResponses(kitTenant()),
			want:      componentsdk.Principal{Provider: "okta", Kind: "api_token", TenantID: kitOrgDomain, AuthMethod: componentsdk.AuthAPIToken, ID: "u1"},
		},
		{
			name: "service app", config: kitOAuthConfig(), secrets: map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()},
			responses: kitOAuthResponses(kitTenant()),
			want: componentsdk.Principal{
				Provider: "okta", Kind: "service_app", TenantID: kitOrgDomain, AuthMethod: componentsdk.AuthPrivateKeyJWT,
				RequestedScopes: []string{
					"okta.apiTokens.read", "okta.apps.read", "okta.authenticators.read", "okta.deviceAssurance.read",
					"okta.eventHooks.read", "okta.groups.read", "okta.idps.read", "okta.inlineHooks.read", "okta.logs.read",
					"okta.networkZones.read", "okta.orgs.read", "okta.policies.read", "okta.roles.read", "okta.users.read",
				},
				Scopes: []string{
					"okta.apps.read", "okta.deviceAssurance.read", "okta.groups.read", "okta.policies.read", "okta.roles.read", "okta.users.read",
				},
				ReadOnly: true,
				ID:       kitClientID,
			},
		},
		{
			// Below the audit level the result has no tenant.
			name: "service app at trust", config: map[string]any{"org_domain": kitOrgDomain, "client_id": kitClientID, "key_id": kitKeyID, "level": "trust"},
			secrets: map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()}, responses: kitOAuthResponses(kitTenant()),
			want: componentsdk.Principal{
				Provider: "okta", Kind: "service_app", AuthMethod: componentsdk.AuthPrivateKeyJWT,
				RequestedScopes: []string{
					"okta.apps.read", "okta.deviceAssurance.read", "okta.groups.read", "okta.policies.read", "okta.roles.read", "okta.users.read",
				},
				Scopes: []string{
					"okta.apps.read", "okta.deviceAssurance.read", "okta.groups.read", "okta.policies.read", "okta.roles.read", "okta.users.read",
				},
				ReadOnly: true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runInProcess(t, tc.config, tc.secrets, tc.responses)
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			if !reflect.DeepEqual(res.Result.SignedInAs, &tc.want) {
				t.Errorf("signed_in_as = %+v, want %+v", res.Result.SignedInAs, tc.want)
			}
		})
	}
}

func TestRunStepsByLevel(t *testing.T) {
	var all []string
	for _, s := range kitSteps {
		all = append(all, s[0])
	}
	// The last eight steps read surfaces only audit and internal collect.
	for level, want := range map[string][]string{"trust": all[:6], "audit": all, "internal": all} {
		res := runInProcess(t, map[string]any{"org_domain": kitOrgDomain, "level": level}, map[string]string{"OKTA_API_TOKEN": kitAPIToken}, kitResponses(kitTenant()))
		if res.ExitCode != 0 || res.Result == nil {
			t.Fatalf("%s: run failed with exit %d: %s", level, res.ExitCode, res.Stderr)
		}
		var got []string
		for _, s := range res.Result.Steps {
			got = append(got, s.Name)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: steps = %v, want %v", level, got, want)
		}
	}
}

// Every level declares the org the config named, at the detailed artifact's
// org_domain, which every level holds. Only the audit level counts it.
func TestRunDeclaresTheConfiguredOrg(t *testing.T) {
	one, complete := 1, true
	for level, count := range map[string]*int{"trust": nil, "audit": &one} {
		res := runInProcess(t, map[string]any{"org_domain": kitOrgDomain, "level": level}, map[string]string{"OKTA_API_TOKEN": kitAPIToken}, kitResponses(kitTenant()))
		if res.ExitCode != 0 || res.Result == nil {
			t.Fatalf("%s: run failed with exit %d: %s", level, res.ExitCode, res.Stderr)
		}
		want := []componentsdk.ResultTarget{{
			Kind: componentsdk.TargetOrganization, ChosenBy: componentsdk.ChosenByConfig, ConfigKey: "org_domain",
			At:    &componentsdk.Location{Path: detailedPath, Pointer: "/org_domain"},
			Count: count, Complete: &complete,
		}}
		if !reflect.DeepEqual(res.Result.Targets, want) {
			got, _ := json.Marshal(res.Result.Targets)
			wanted, _ := json.Marshal(want)
			t.Errorf("%s: targets = %s, want %s", level, got, wanted)
		}
		for _, f := range res.Result.Checks {
			t.Errorf("%s: check finding %+v", level, f)
		}
	}
}

// A trust run's diagnostics name no user, policy, or group by ID, and leave
// out the error text that names them, in any artifact. An audit run still
// names each one.
func TestATrustRunWritesNoOktaIDs(t *testing.T) {
	const (
		failingUser = "00ukitfailing0000001"
		missingUser = "00ukitmissing0000001"
		policy      = "00pkitpolicy00000001"
		group       = "00gkitgroup000000001"
	)
	tenant := kitTenant()
	tenant.users = append(tenant.users, okta.User{ID: failingUser, Status: "ACTIVE", Created: kitNow, LastLogin: kitNow, Profile: okta.UserProfile{Login: "grace@acme.com"}})
	tenant.roleAssignees = append(tenant.roleAssignees, okta.RoleAssignedUser{ID: failingUser}, okta.RoleAssignedUser{ID: missingUser})
	tenant.policies[PolicyTypeMFAEnroll] = append(tenant.policies[PolicyTypeMFAEnroll], okta.Policy{ID: policy, Name: "Contractors", Type: PolicyTypeMFAEnroll, Status: "ACTIVE", Priority: 2})
	tenant.policies[PolicyTypeSignOn] = append(tenant.policies[PolicyTypeSignOn], okta.Policy{ID: "p4", Name: "Contractors", Type: PolicyTypeSignOn, Status: "ACTIVE", Priority: 3,
		Conditions: okta.PolicyConditions{People: &okta.PolicyPeopleCondition{Groups: &struct {
			Include []string `json:"include,omitempty"`
			Exclude []string `json:"exclude,omitempty"`
		}{Include: []string{group}}}}})
	notFound := func(path, id, kind string) collectortest.Response {
		return collectortest.Response{URL: kitBase + path, Status: http.StatusNotFound, Body: kitJSON(map[string]any{
			"errorCode": "E0000007", "errorSummary": "Not found: Resource not found: " + id + " (" + kind + ")",
			"errorLink": "E0000007", "errorId": "oae-kit-missing", "errorCauses": []any{},
		})}
	}
	responses := append([]collectortest.Response{
		notFound("/api/v1/users/"+failingUser+"/factors", failingUser, "User"),
		notFound("/api/v1/users/"+failingUser+"/roles", failingUser, "User"),
		notFound("/api/v1/policies/"+policy+"/rules", policy, "Policy"),
		notFound("/api/v1/groups/"+group+"/users?limit=200", group, "UserGroup"),
	}, kitResponses(tenant)...)
	ids := []string{failingUser, missingUser, policy, group}

	warnings := func(res componentsdk.InProcessResult) []string {
		t.Helper()
		for _, a := range res.Artifacts {
			if a.Path != detailedPath {
				continue
			}
			var out OrgPosture
			if err := json.Unmarshal(a.Data, &out); err != nil {
				t.Fatal(err)
			}
			if out.Diagnostics == nil {
				return nil
			}
			return out.Diagnostics.Warnings
		}
		t.Fatalf("no %s", detailedPath)
		return nil
	}

	trust := runInProcess(t, map[string]any{"org_domain": kitOrgDomain, "level": "trust"}, map[string]string{"OKTA_API_TOKEN": kitAPIToken}, responses)
	if trust.ExitCode != 0 {
		t.Fatalf("the trust run failed with exit %d: %s", trust.ExitCode, trust.Stderr)
	}
	for _, a := range trust.Artifacts {
		for _, id := range ids {
			if strings.Contains(string(a.Data), id) {
				t.Errorf("the trust run wrote %s in %s", id, a.Path)
			}
		}
	}
	got := warnings(trust)
	for _, want := range []string{
		"a user: failed to fetch MFA factors: okta API returned status 404: E0000007",
		"privileged access: a role-assigned user missing from user inventory; skipping",
		"privileged access: failed to fetch roles for a user: okta API returned status 404: E0000007",
		"MFA-enrollment policies: okta API returned status 404: E0000007",
		"policy group memberships: okta API returned status 404: E0000007",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("the trust run's warnings %q do not include %q", got, want)
		}
	}

	audit := runInProcess(t, map[string]any{"org_domain": kitOrgDomain, "level": "audit"}, map[string]string{"OKTA_API_TOKEN": kitAPIToken}, responses)
	if audit.ExitCode != 0 {
		t.Fatalf("the audit run failed with exit %d: %s", audit.ExitCode, audit.Stderr)
	}
	got = warnings(audit)
	for _, want := range []string{
		"user " + failingUser + ": failed to fetch MFA factors: okta API /api/v1/users/" + failingUser + "/factors returned status 404: E0000007 Not found: Resource not found: " + failingUser + " (User)",
		"privileged access: role-assigned user " + missingUser + " missing from user inventory; skipping",
		"privileged access: failed to fetch roles for user " + failingUser + ": okta API /api/v1/users/" + failingUser + "/roles returned status 404: E0000007 Not found: Resource not found: " + failingUser + " (User)",
		"MFA-enrollment policies: okta API /api/v1/policies/" + policy + "/rules returned status 404: E0000007 Not found: Resource not found: " + policy + " (Policy)",
		"policy group memberships: okta API /api/v1/groups/" + group + "/users returned status 404: E0000007 Not found: Resource not found: " + group + " (UserGroup)",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("the audit run's warnings %q do not include %q", got, want)
		}
	}
}

func TestReadOnlyNeedsAServiceAppGrantedOnlyTheReadScopesItAskedFor(t *testing.T) {
	asked := []string{"okta.logs.read", "okta.users.read"}
	cases := []struct {
		name string
		id   okta.Identity
		want bool
	}{
		{"api token", okta.Identity{AuthMethod: componentsdk.AuthAPIToken}, false},
		{"granted part of what it asked for", okta.Identity{AuthMethod: componentsdk.AuthPrivateKeyJWT, RequestedScopes: asked, Scopes: []string{"okta.users.read"}}, true},
		{"granted a scope it did not ask for", okta.Identity{AuthMethod: componentsdk.AuthPrivateKeyJWT, RequestedScopes: asked, Scopes: []string{"okta.users.read", "okta.users.manage"}}, false},
		{"asked for a write scope", okta.Identity{AuthMethod: componentsdk.AuthPrivateKeyJWT, RequestedScopes: []string{"okta.users.manage"}}, false},
	}
	for _, tc := range cases {
		if got := readOnly(&tc.id); got != tc.want {
			t.Errorf("%s: readOnly = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestEachCallDeclaresItsScope checks that each management API call lists
// the OAuth scope Okta's API reference gives for it, and that the two
// sign-in calls list none.
func TestEachCallDeclaresItsScope(t *testing.T) {
	want := map[string]string{
		"okta.token.create":               "",
		"okta.users.list":                 "okta.users.read",
		"okta.users.factors.list":         "okta.users.read",
		"okta.users.groups.list":          "okta.users.read",
		"okta.users.roles.list":           "okta.roles.read",
		"okta.iam.assignees.list":         "okta.roles.read",
		"okta.iam.roles.list":             "okta.roles.read",
		"okta.iam.roles.permissions.list": "okta.roles.read",
		"okta.apps.list":                  "okta.apps.read",
		"okta.policies.list":              "okta.policies.read",
		"okta.policies.rules.list":        "okta.policies.read",
		"okta.groups.list":                "okta.groups.read",
		"okta.groups.users.list":          "okta.groups.read",
		"okta.device_assurances.list":     "okta.deviceAssurance.read",
		"okta.authenticators.list":        "okta.authenticators.read",
		"okta.zones.list":                 "okta.networkZones.read",
		"okta.idps.list":                  "okta.idps.read",
		"okta.api_tokens.list":            "okta.apiTokens.read",
		"okta.event_hooks.list":           "okta.eventHooks.read",
		"okta.inline_hooks.list":          "okta.inlineHooks.read",
		"okta.logs.list":                  "okta.logs.read",
		"okta.org.get":                    "okta.orgs.read",
		"okta.org.contacts.get":           "okta.orgs.read",
	}
	res := runInProcess(t, kitOAuthConfig(), map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()}, kitOAuthResponses(kitTenant()))
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	got := map[string]string{}
	for _, op := range res.Operations {
		got[op.Name] = op.Permission
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("declared scopes = %v, want %v", got, want)
	}
	if scope := okta.Scope("okta.users.me.get"); scope != "" {
		t.Errorf("the API token sign-in declares %q, want none", scope)
	}
}

func runInProcess(t *testing.T, config map[string]any, secrets map[string]string, responses []collectortest.Response) componentsdk.InProcessResult {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    config,
		Secrets:   secrets,
		Transport: replay,
		Seed:      1,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		Clock:     func() time.Time { return kitNow },
	})
	for _, request := range replay.Unmatched() {
		t.Errorf("no canned response for %s", request)
	}
	return res
}

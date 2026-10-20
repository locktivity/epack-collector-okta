package collector

import (
	"context"
	"reflect"
	"slices"
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
			name: "service app at trust", config: map[string]any{"org_domain": kitOrgDomain, "client_id": kitClientID, "key_id": kitKeyID, "level": "trust"},
			secrets: map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()}, responses: kitOAuthResponses(kitTenant()),
			want: componentsdk.Principal{
				Provider: "okta", Kind: "service_app", TenantID: kitOrgDomain, AuthMethod: componentsdk.AuthPrivateKeyJWT,
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

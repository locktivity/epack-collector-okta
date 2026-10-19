package collector

import (
	"context"
	"reflect"
	"testing"
	"time"

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
			want:      componentsdk.Principal{Provider: "okta", Kind: "api_token", TenantID: kitOrgDomain, ID: "u1"},
		},
		{
			name: "service app", config: kitOAuthConfig(), secrets: map[string]string{"OKTA_PRIVATE_KEY": kitPrivateKey()},
			responses: kitOAuthResponses(kitTenant()),
			want: componentsdk.Principal{Provider: "okta", Kind: "service_app", TenantID: kitOrgDomain, ID: kitClientID, Scopes: []string{
				"okta.apps.read", "okta.deviceAssurance.read", "okta.groups.read", "okta.policies.read", "okta.roles.read", "okta.users.read",
			}},
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

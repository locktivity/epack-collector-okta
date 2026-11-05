package collector

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

func TestOrgSettings_SelfServiceRecoveryFromPasswordRules(t *testing.T) {
	allow := &okta.RuleAccess{Access: "ALLOW"}
	deny := &okta.RuleAccess{Access: "DENY"}
	tests := []struct {
		name  string
		rules []okta.PolicyRule
		want  bool
	}{
		{"reset allowed", []okta.PolicyRule{{Status: "ACTIVE", Actions: okta.PolicyRuleActions{SelfServicePasswordReset: allow, SelfServiceUnlock: deny}}}, true},
		{"unlock allowed", []okta.PolicyRule{{Status: "ACTIVE", Actions: okta.PolicyRuleActions{SelfServicePasswordReset: deny, SelfServiceUnlock: allow}}}, true},
		{"both denied", []okta.PolicyRule{{Status: "ACTIVE", Actions: okta.PolicyRuleActions{SelfServicePasswordReset: deny, SelfServiceUnlock: deny}}}, false},
		{"only an inactive rule allows", []okta.PolicyRule{{Status: "INACTIVE", Actions: okta.PolicyRuleActions{SelfServicePasswordReset: allow}}}, false},
		{"no rules", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockOktaClient{
				orgSettings: &okta.OrgSettings{Subdomain: "acme", Status: "ACTIVE"},
				users:       []okta.User{{ID: "u1", Status: "ACTIVE", Profile: okta.UserProfile{Login: "u1@acme.com"}}},
				policies: map[string][]okta.Policy{
					PolicyTypePassword: {{ID: "pw1", Name: "Default Policy", Type: PolicyTypePassword, Status: "ACTIVE", Priority: 1}},
				},
				policyRules: map[string][]okta.PolicyRule{"pw1": tt.rules},
			}
			posture, err := NewWithClient(Config{OrgDomain: "acme.okta.com"}, client).Collect(context.Background(), componentsdk.LevelAudit)
			if err != nil {
				t.Fatalf("collect: %v", err)
			}
			assertBool(t, "SelfServiceRecoveryEnabled", posture.OrgSettings.SelfServiceRecoveryEnabled, tt.want)
		})
	}
}

func TestOrgSettings_SelfServiceRecoveryLeftOutWhenPoliciesFail(t *testing.T) {
	client := &mockOktaClient{
		orgSettings: &okta.OrgSettings{Subdomain: "acme", Status: "ACTIVE"},
		policiesErr: &okta.APIStatusError{StatusCode: 403, Path: "/api/v1/policies"},
	}
	rec := &componentsdk.Recorder{}
	posture, err := NewWithClient(Config{OrgDomain: "acme.okta.com", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if posture.OrgSettings.SelfServiceRecoveryEnabled != nil {
		t.Errorf("self_service_recovery_enabled = %v, want it left out", *posture.OrgSettings.SelfServiceRecoveryEnabled)
	}
	if _, ok := gapAt(rec, "/org_settings/self_service_recovery_enabled"); !ok {
		t.Errorf("expected a gap at /org_settings/self_service_recovery_enabled, got %+v", rec.Gaps())
	}
}

// selfServiceRecovery collects org settings at audit against password
// policies and rules given as Okta sends them. Both users are in g-all, and
// only u2 is in g-ops.
func selfServiceRecovery(t *testing.T, policiesJSON, rulesJSON string) *bool {
	t.Helper()
	var policies []okta.Policy
	if err := json.Unmarshal([]byte(policiesJSON), &policies); err != nil {
		t.Fatalf("decoding policies: %v", err)
	}
	var rules map[string][]okta.PolicyRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		t.Fatalf("decoding rules: %v", err)
	}
	u1 := okta.User{ID: "u1", Status: "ACTIVE", Profile: okta.UserProfile{Login: "u1@acme.com"}}
	u2 := okta.User{ID: "u2", Status: "ACTIVE", Profile: okta.UserProfile{Login: "u2@acme.com"}}
	client := &mockOktaClient{
		orgSettings: &okta.OrgSettings{ID: "00o1", Subdomain: "acme", Status: "ACTIVE"},
		users:       []okta.User{u1, u2},
		groupUsers:  map[string][]okta.User{"g-all": {u1, u2}, "g-ops": {u2}},
		policies:    map[string][]okta.Policy{PolicyTypePassword: policies},
		policyRules: rules,
	}
	posture, err := NewWithClient(Config{OrgDomain: "acme.okta.com"}, client).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return posture.OrgSettings.SelfServiceRecoveryEnabled
}

const (
	recoveryDenied  = `{"selfServicePasswordReset":{"access":"DENY"},"selfServiceUnlock":{"access":"DENY"}}`
	recoveryAllowed = `{"selfServicePasswordReset":{"access":"ALLOW"},"selfServiceUnlock":{"access":"DENY"}}`
)

// Okta applies the first password policy that matches a person. A lower
// policy for the same people never applies.
func TestOrgSettings_SelfServiceRecoveryFollowsPolicyOrder(t *testing.T) {
	rules := `{
		"p-corp":[{"id":"r1","status":"ACTIVE","priority":1,"actions":` + recoveryDenied + `}],
		"p-default":[{"id":"r2","status":"ACTIVE","priority":1,"system":true,"actions":` + recoveryAllowed + `}]
	}`
	tests := []struct {
		name      string
		corpGroup string
		want      bool
	}{
		{"first policy covers everyone", "g-all", false},
		{"first policy covers one group", "g-ops", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selfServiceRecovery(t, `[
				{"id":"p-corp","name":"Corporate","status":"ACTIVE","priority":1,"conditions":{"people":{"groups":{"include":["`+tt.corpGroup+`"]}}}},
				{"id":"p-default","name":"Default Policy","status":"ACTIVE","priority":2,"system":true,"conditions":{"people":{"groups":{"include":["g-all"]}}}}
			]`, rules)
			assertBool(t, "SelfServiceRecoveryEnabled", got, tt.want)
		})
	}
}

// Within a policy, Okta applies the first rule whose conditions are met. A
// rule for sign-ins from one network zone leaves sign-ins from elsewhere to
// the next rule.
func TestOrgSettings_SelfServiceRecoveryFollowsRuleOrder(t *testing.T) {
	tests := []struct {
		name    string
		network string
		want    bool
	}{
		{"first rule covers every sign-in", `{"connection":"ANYWHERE"}`, false},
		{"first rule covers one zone", `{"connection":"ZONE","include":["nz-office"]}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selfServiceRecovery(t, `[
				{"id":"p-default","name":"Default Policy","status":"ACTIVE","priority":1,"system":true,"conditions":{"people":{"groups":{"include":["g-all"]}}}}
			]`, `{
				"p-default":[
					{"id":"r1","name":"No self-service","status":"ACTIVE","priority":1,"conditions":{"people":{"users":{"exclude":[]}},"network":`+tt.network+`},"actions":`+recoveryDenied+`},
					{"id":"r2","name":"Default Rule","status":"ACTIVE","priority":2,"system":true,"conditions":{"people":{"users":{"exclude":[]}},"network":{"connection":"ANYWHERE"}},"actions":`+recoveryAllowed+`}
				]
			}`)
			assertBool(t, "SelfServiceRecoveryEnabled", got, tt.want)
		})
	}
}

// Who a password policy applies to takes the user list, so the flag is left
// out with a gap when the list cannot be read.
func TestOrgSettings_SelfServiceRecoveryLeftOutWhenUsersFail(t *testing.T) {
	client := &mockOktaClient{
		orgSettings: &okta.OrgSettings{Subdomain: "acme", Status: "ACTIVE"},
		usersErr:    &okta.APIStatusError{StatusCode: 403, Path: "/api/v1/users"},
		policies: map[string][]okta.Policy{
			PolicyTypePassword: {{ID: "pw1", Name: "Default Policy", Type: PolicyTypePassword, Status: "ACTIVE", Priority: 1}},
		},
		policyRules: map[string][]okta.PolicyRule{"pw1": {{Status: "ACTIVE", Actions: okta.PolicyRuleActions{SelfServicePasswordReset: &okta.RuleAccess{Access: "ALLOW"}}}}},
	}
	rec := &componentsdk.Recorder{}
	posture, err := NewWithClient(Config{OrgDomain: "acme.okta.com", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if posture.OrgSettings.SelfServiceRecoveryEnabled != nil {
		t.Errorf("self_service_recovery_enabled = %v, want it left out", *posture.OrgSettings.SelfServiceRecoveryEnabled)
	}
	if _, ok := gapAt(rec, "/org_settings/self_service_recovery_enabled"); !ok {
		t.Errorf("expected a gap at /org_settings/self_service_recovery_enabled, got %+v", rec.Gaps())
	}
}

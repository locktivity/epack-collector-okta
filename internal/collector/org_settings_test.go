package collector

import (
	"context"
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

package collector

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// richClient returns a mock populated across every surface, with forbidden
// source values (PII, signing keys, hook auth headers, full URLs) embedded so
// privacy tests can assert they never reach the output.
func richClient() *mockOktaClient {
	return richClientAt(time.Now())
}

// richClientAt is richClient with its timestamps at now.
func richClientAt(now time.Time) *mockOktaClient {
	return &mockOktaClient{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastLogin: now, Created: now, Profile: okta.UserProfile{
				Login: "alice@acme.com", FirstName: "Alice", LastName: "Anderson", UserType: "Employee",
			}},
		},
		factors: map[string][]okta.Factor{
			"u1": {{ID: "f1", FactorType: "webauthn", Status: "ACTIVE", Created: now}},
		},
		userGroupIDs:  map[string][]string{"u1": {"g1"}},
		roleAssignees: []okta.RoleAssignedUser{{ID: "u1"}},
		userRoles:     map[string][]okta.RoleAssignment{"u1": {{Type: "SUPER_ADMIN", AssignmentType: "USER"}}},
		apps: []okta.Application{
			{ID: "app1", Label: "Web App", Name: "web_app", SignOnMode: "SAML_2_0", Status: "ACTIVE"},
		},
		policies: map[string][]okta.Policy{
			"OKTA_SIGN_ON": {{ID: "p1", Name: "Default", Type: "OKTA_SIGN_ON", Status: "ACTIVE", Priority: 1}},
			"PASSWORD":     {{ID: "pw1", Name: "Default", Type: "PASSWORD", Status: "ACTIVE", Priority: 1}},
		},
		policyRules: map[string][]okta.PolicyRule{
			"p1":  {{ID: "r1", Name: "MFA", Status: "ACTIVE", Actions: okta.PolicyRuleActions{Signon: &okta.SignonActions{RequireFactor: true}}}},
			"pw1": {{ID: "r2", Name: "Default Rule", Status: "ACTIVE", Actions: okta.PolicyRuleActions{SelfServicePasswordReset: &okta.RuleAccess{Access: "ALLOW"}}}},
		},
		authenticators:          []okta.Authenticator{{Key: "webauthn", Status: "ACTIVE"}},
		deviceAssurancePolicies: []okta.DeviceAssurancePolicy{{ID: "d1", Name: "iOS", Platform: "IOS"}},
		groups: []okta.Group{
			{ID: "g1", Type: "OKTA_GROUP", Profile: okta.GroupProfile{Name: "Admins"}, Embedded: stats(1)},
		},
		groupUsers: map[string][]okta.User{"g1": {{Profile: okta.UserProfile{Login: "alice@acme.com"}}}},
		networkZones: []okta.NetworkZone{
			{ID: "z1", Name: "Office", Type: "IP", Status: "ACTIVE", Usage: "POLICY",
				Gateways: json.RawMessage(`[{"type":"CIDR","value":"10.0.0.0/8"}]`)},
		},
		identityProviders: []okta.IdentityProvider{
			func() okta.IdentityProvider {
				idp := okta.IdentityProvider{ID: "idp1", Name: "Corp SAML", Type: "SAML2", Status: "ACTIVE"}
				idp.Protocol.Credentials.Trust.Issuer = "https://idp.example.com/saml/SECRETKEYMATERIAL"
				idp.Protocol.Credentials.Trust.Kid = "kid-abc123"
				idp.Protocol.Endpoints.SSO.URL = "https://idp.example.com/sso?token=SECRETSSOTOKEN"
				idp.Policy.Provisioning.Action = "AUTO"
				return idp
			}(),
		},
		apiTokens: []okta.APIToken{
			{ID: "tok1", Name: "ci-token", Status: "ACTIVE", Created: now, LastUpdated: now, UserID: "u1"},
		},
		eventHooks: []okta.EventHook{
			func() okta.EventHook {
				h := okta.EventHook{ID: "eh1", Name: "Notify", Status: "ACTIVE"}
				h.Events.Items = []string{"user.lifecycle.create"}
				h.Channel.Type = "HTTP"
				h.Channel.Config.URI = "https://hooks.example.com/path/SECRETHOOKPATH"
				h.Channel.Config.Headers = []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				}{{Key: "Authorization", Value: "Bearer SECRETHOOKAUTH"}}
				return h
			}(),
		},
		systemLog: []okta.LogEvent{
			{UUID: "e1", Published: now, EventType: "user.account.lock", Actor: struct {
				AlternateID string `json:"alternateId"`
				Type        string `json:"type"`
			}{AlternateID: "alice@acme.com", Type: "User"}},
		},
		orgSettings: &okta.OrgSettings{Subdomain: "acme", Status: "ACTIVE"},
		orgContacts: []okta.OrgContact{{Type: "TECHNICAL", UserID: "u1"}},
	}
}

func collectAt(t *testing.T, level componentsdk.Level) *OrgPosture {
	t.Helper()
	c := NewWithClient(Config{OrgDomain: "acme.okta.com"}, richClient())
	posture, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("collect at %s: %v", level, err)
	}
	return posture
}

func TestLevels_TrustBoundary(t *testing.T) {
	p := collectAt(t, componentsdk.LevelTrust)

	if p.CollectedAtLevel != "trust" {
		t.Errorf("collected_at_level = %q, want trust", p.CollectedAtLevel)
	}

	// Existing surfaces: no audit/internal fields populated.
	if p.Users.Inventory != nil || p.Apps.Inventory != nil || p.Posture.PerFactorType != nil {
		t.Error("trust must not populate existing-surface audit fields")
	}
	if len(p.PrivilegedAccess.Inventory) != 0 || len(p.Policy.Policies) != 0 || len(p.DeviceAccess.Policies) != 0 {
		t.Error("trust must not populate per-entity inventories")
	}

	// New surfaces are collected at audit and above; trust omits them entirely.
	if p.Groups != nil || p.NetworkZones != nil || p.IdentityProviders != nil ||
		p.APITokens != nil || p.Hooks != nil || p.SystemLog != nil || p.OrgSettings != nil {
		t.Error("trust must omit the audit+ surfaces")
	}
}

func TestLevels_AuditShapes(t *testing.T) {
	p := collectAt(t, componentsdk.LevelAudit)

	// Audit arrays are non-nil (normalized) but carry no internal per-row detail.
	if p.Users.Inventory == nil {
		t.Fatal("expected non-nil user inventory at audit")
	}
	if len(p.Users.Inventory) > 0 && (p.Users.Inventory[0].Factors != nil || p.Users.Inventory[0].LastLoginAt != "" || p.Users.Inventory[0].HasActiveMFA != nil) {
		t.Error("audit must not populate internal per-user fields")
	}
	if len(p.PrivilegedAccess.Inventory) > 0 && (p.PrivilegedAccess.Inventory[0].HasActiveMFA != nil || p.PrivilegedAccess.Inventory[0].HasPhishingResistantMFA != nil) {
		t.Error("audit must not carry the admins' MFA flags")
	}
	if p.SystemLog == nil || p.SystemLog.CountByCategory == nil {
		t.Error("system_log audit counts expected")
	}
	if len(p.SystemLog.Events) != 0 {
		t.Error("system_log events are internal-only")
	}
	if p.IdentityProviders.Inventory[0].SigningCertThumbprint != "" {
		t.Error("idp thumbprint is internal-only")
	}
}

func TestLevels_InternalShapes(t *testing.T) {
	p := collectAt(t, componentsdk.LevelInternal)

	if len(p.Users.Inventory) == 0 || len(p.Users.Inventory[0].Factors) == 0 {
		t.Error("internal expected per-user factors")
	}
	if len(p.Users.Inventory[0].GroupIDs) == 0 {
		t.Error("internal expected per-user group IDs")
	}
	if len(p.SystemLog.Events) == 0 {
		t.Error("internal expected system_log events")
	}
	if p.IdentityProviders.Inventory[0].SigningCertThumbprint == "" {
		t.Error("internal expected idp thumbprint (kid)")
	}
}

// TestPrivacy_ForbiddenDataNeverEmitted runs a full internal collection over
// fixtures that embed PII and secrets, then asserts none of those values appear
// anywhere in the marshaled artifact.
func TestPrivacy_ForbiddenDataNeverEmitted(t *testing.T) {
	p := collectAt(t, componentsdk.LevelInternal)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(data)

	forbidden := map[string]string{
		"user first name":      "Alice",
		"user last name":       "Anderson",
		"raw userType":         "Employee",
		"idp signing material": "SECRETKEYMATERIAL",
		"idp full SSO token":   "SECRETSSOTOKEN",
		"hook full path":       "SECRETHOOKPATH",
		"hook auth header":     "SECRETHOOKAUTH",
	}
	for label, value := range forbidden {
		if strings.Contains(out, value) {
			t.Errorf("forbidden %s leaked into output: %q", label, value)
		}
	}

	// Logins (the one allowed identifier) should be present.
	if !strings.Contains(out, "alice@acme.com") {
		t.Error("expected login to be present in output")
	}
}

func TestIdPs_NeverEmitsSigningKeys(t *testing.T) {
	p := collectAt(t, componentsdk.LevelInternal)
	idp := p.IdentityProviders.Inventory[0]
	if idp.IssuerHost != "idp.example.com" {
		t.Errorf("expected host-only issuer, got %q", idp.IssuerHost)
	}
	if strings.Contains(idp.IssuerHost, "SECRET") || strings.Contains(idp.SigningCertThumbprint, "SECRET") {
		t.Error("idp surface leaked secret material")
	}
}

func TestHooks_NeverEmitsFullURLOrAuthHeaders(t *testing.T) {
	p := collectAt(t, componentsdk.LevelInternal)
	hook := p.Hooks.EventHooks[0]
	if hook.EndpointHost != "hooks.example.com" {
		t.Errorf("expected host-only endpoint, got %q", hook.EndpointHost)
	}
	data, _ := json.Marshal(p.Hooks)
	if strings.Contains(string(data), "Authorization") || strings.Contains(string(data), "SECRETHOOK") {
		t.Error("hooks surface leaked auth header or full URL")
	}
}

func TestAPITokens_DegradesOnInsufficientScope(t *testing.T) {
	client := richClient()
	client.apiTokensErr = &okta.APIStatusError{StatusCode: 403, Path: "/api/v1/api-tokens"}

	c := NewWithClient(Config{OrgDomain: "acme.okta.com"}, client)
	p, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("expected graceful degradation, got: %v", err)
	}
	if p.APITokens != nil {
		t.Error("api_tokens surface should be omitted on 403")
	}
	if p.Diagnostics == nil {
		t.Fatal("expected diagnostic for api-token scope denial")
	}
	found := false
	for _, w := range p.Diagnostics.Warnings {
		if strings.Contains(w, "SUPER_ADMIN") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SUPER_ADMIN scope diagnostic, got %v", p.Diagnostics.Warnings)
	}
}

func TestSystemLog_FilterOnlySecurityCategories(t *testing.T) {
	filter := buildSystemLogFilter()

	// Every clause is an eventType equality over a known security event type.
	for _, clause := range strings.Split(filter, " or ") {
		if !strings.HasPrefix(clause, "eventType eq ") {
			t.Errorf("unexpected filter clause: %q", clause)
		}
	}
	// Spot-check representative event types are present.
	for _, want := range []string{"user.account.lock", "policy.lifecycle.create", "system.api_token.create", "security.zone.create"} {
		if !strings.Contains(filter, want) {
			t.Errorf("filter missing security event type %q", want)
		}
	}
	// And that nothing non-security (e.g. routine app access) sneaks in.
	if strings.Contains(filter, "user.authentication.sso") {
		t.Error("filter must not include routine authentication events")
	}
}

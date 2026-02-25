package collector

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
)

// mockOktaClient implements okta.OktaClient for testing.
type mockOktaClient struct {
	users       []okta.User
	usersErr    error
	factors     map[string][]okta.Factor // userID -> factors
	factorsErr  error
	apps        []okta.Application
	appsErr     error
	policies    map[string][]okta.Policy // policyType -> policies
	policiesErr error
	policyRules map[string][]okta.PolicyRule // policyID -> rules
	rulesErr    error
	orgSettings *okta.OrgSettings
	orgErr      error
}

func (m *mockOktaClient) FetchUsers(ctx context.Context, callback func([]okta.User) error) error {
	if m.usersErr != nil {
		return m.usersErr
	}
	return callback(m.users)
}

func (m *mockOktaClient) FetchUserFactors(ctx context.Context, userID string) ([]okta.Factor, error) {
	if m.factorsErr != nil {
		return nil, m.factorsErr
	}
	return m.factors[userID], nil
}

func (m *mockOktaClient) FetchApplications(ctx context.Context, callback func([]okta.Application) error) error {
	if m.appsErr != nil {
		return m.appsErr
	}
	return callback(m.apps)
}

func (m *mockOktaClient) FetchPolicies(ctx context.Context, policyType string) ([]okta.Policy, error) {
	if m.policiesErr != nil {
		return nil, m.policiesErr
	}
	return m.policies[policyType], nil
}

func (m *mockOktaClient) FetchPolicyRules(ctx context.Context, policyID string) ([]okta.PolicyRule, error) {
	if m.rulesErr != nil {
		return nil, m.rulesErr
	}
	return m.policyRules[policyID], nil
}

func (m *mockOktaClient) FetchOrgSettings(ctx context.Context) (*okta.OrgSettings, error) {
	if m.orgErr != nil {
		return nil, m.orgErr
	}
	return m.orgSettings, nil
}

func TestCollect_EmptyOrganization(t *testing.T) {
	client := &mockOktaClient{
		users:    []okta.User{},
		factors:  make(map[string][]okta.Factor),
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.OrgDomain != "test.okta.com" {
		t.Errorf("expected org_domain=test.okta.com, got %s", posture.OrgDomain)
	}

	// All percentages should be 0 for empty org
	if posture.Posture.MFACoverage != 0 {
		t.Errorf("expected 0%% MFA coverage, got %d%%", posture.Posture.MFACoverage)
	}

	if posture.Posture.SSOCoverage != 0 {
		t.Errorf("expected 0%% SSO coverage, got %d%%", posture.Posture.SSOCoverage)
	}
}

func TestCollect_WithUsers(t *testing.T) {
	now := time.Now()
	recentLogin := now.AddDate(0, 0, -30) // 30 days ago
	oldLogin := now.AddDate(0, 0, -120)   // 120 days ago (inactive)

	client := &mockOktaClient{
		users: []okta.User{
			{ID: "user1", Status: "ACTIVE", LastLogin: recentLogin},
			{ID: "user2", Status: "ACTIVE", LastLogin: recentLogin},
			{ID: "user3", Status: "ACTIVE", LastLogin: oldLogin},
			{ID: "user4", Status: "LOCKED_OUT", LastLogin: recentLogin},
			{ID: "user5", Status: "DEPROVISIONED", LastLogin: recentLogin}, // Should be skipped
		},
		factors: map[string][]okta.Factor{
			"user1": {{ID: "f1", FactorType: "push", Status: "ACTIVE", Provider: "OKTA"}},
			"user2": {{ID: "f2", FactorType: "sms", Status: "ACTIVE"}},
			"user3": {}, // No MFA
			"user4": {{ID: "f3", FactorType: "webauthn", Status: "ACTIVE"}},
		},
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3 users with MFA (user1, user2, user4) out of 4
	// MFA coverage = 75%
	if posture.Posture.MFACoverage != 75 {
		t.Errorf("expected 75%% MFA coverage, got %d%%", posture.Posture.MFACoverage)
	}

	// Only user4 has phishing-resistant MFA (webauthn) = 25%
	if posture.Posture.MFAPhishingResistant != 25 {
		t.Errorf("expected 25%% phishing resistant, got %d%%", posture.Posture.MFAPhishingResistant)
	}

	// 1 user locked out = 25%
	if posture.Users.LockedOut != 25 {
		t.Errorf("expected 25%% locked out, got %d%%", posture.Users.LockedOut)
	}

	// 1 user inactive (user3) = 25%
	if posture.Users.Inactive != 25 {
		t.Errorf("expected 25%% inactive, got %d%%", posture.Users.Inactive)
	}
}

func TestCollect_WithApps(t *testing.T) {
	client := &mockOktaClient{
		users:   []okta.User{},
		factors: make(map[string][]okta.Factor),
		apps: []okta.Application{
			{ID: "app1", SignOnMode: "SAML_2_0", Status: "ACTIVE", Features: []string{"PUSH_NEW_USERS"}},
			{ID: "app2", SignOnMode: "OPENID_CONNECT", Status: "ACTIVE"},
			{ID: "app3", SignOnMode: "BROWSER_PLUGIN", Status: "ACTIVE"}, // SWA - not SSO
			{ID: "app4", SignOnMode: "WS_FEDERATION", Status: "ACTIVE", Features: []string{"PUSH_USER_DEACTIVATION"}},
		},
		policies: make(map[string][]okta.Policy),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SSO coverage = SAML + OIDC + WS-Fed = 3/4 = 75%
	if posture.Posture.SSOCoverage != 75 {
		t.Errorf("expected 75%% SSO coverage, got %d%%", posture.Posture.SSOCoverage)
	}

	// 1 app with provisioning = 25%
	if posture.Apps.ProvisioningEnabled != 25 {
		t.Errorf("expected 25%% provisioning enabled, got %d%%", posture.Apps.ProvisioningEnabled)
	}

	// 1 app with deprovisioning = 25%
	if posture.Apps.DeprovisioningEnabled != 25 {
		t.Errorf("expected 25%% deprovisioning enabled, got %d%%", posture.Apps.DeprovisioningEnabled)
	}
}

func TestCollect_WithPolicy(t *testing.T) {
	client := &mockOktaClient{
		users:   []okta.User{},
		factors: make(map[string][]okta.Factor),
		apps:    []okta.Application{},
		policies: map[string][]okta.Policy{
			"OKTA_SIGN_ON": {
				{
					ID:     "policy1",
					Status: "ACTIVE",
				},
			},
		},
		policyRules: map[string][]okta.PolicyRule{
			"policy1": {
				{
					ID:     "rule1",
					Status: "ACTIVE",
					Actions: okta.PolicyRuleActions{
						Signon: &okta.SignonActions{
							RequireFactor: true,
							Session: struct {
								UsePersistentCookie       bool `json:"usePersistentCookie"`
								MaxSessionIdleMinutes     int  `json:"maxSessionIdleMinutes"`
								MaxSessionLifetimeMinutes int  `json:"maxSessionLifetimeMinutes"`
							}{
								MaxSessionLifetimeMinutes: 1440,
								MaxSessionIdleMinutes:     120,
							},
						},
					},
				},
			},
		},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.Policy.PolicyCount != 1 {
		t.Errorf("expected policy count 1, got %d", posture.Policy.PolicyCount)
	}

	if !posture.Policy.MFARequiredAll {
		t.Error("expected MFA required all to be true")
	}

	if !posture.Policy.MFARequiredAny {
		t.Error("expected MFA required any to be true")
	}

	if posture.Policy.SessionLifetimeMinMinutes == nil || *posture.Policy.SessionLifetimeMinMinutes != 1440 {
		t.Errorf("expected session lifetime min 1440, got %v", posture.Policy.SessionLifetimeMinMinutes)
	}

	if posture.Policy.SessionLifetimeMaxMinutes == nil || *posture.Policy.SessionLifetimeMaxMinutes != 1440 {
		t.Errorf("expected session lifetime max 1440, got %v", posture.Policy.SessionLifetimeMaxMinutes)
	}

	if posture.Policy.IdleTimeoutMinMinutes == nil || *posture.Policy.IdleTimeoutMinMinutes != 120 {
		t.Errorf("expected idle timeout min 120, got %v", posture.Policy.IdleTimeoutMinMinutes)
	}

	if posture.Policy.IdleTimeoutMaxMinutes == nil || *posture.Policy.IdleTimeoutMaxMinutes != 120 {
		t.Errorf("expected idle timeout max 120, got %v", posture.Policy.IdleTimeoutMaxMinutes)
	}
}

func TestCollect_WithMultiplePolicies(t *testing.T) {
	client := &mockOktaClient{
		users:   []okta.User{},
		factors: make(map[string][]okta.Factor),
		apps:    []okta.Application{},
		policies: map[string][]okta.Policy{
			"OKTA_SIGN_ON": {
				{
					ID:     "default-policy",
					Status: "ACTIVE",
				},
				{
					ID:     "admins-policy",
					Status: "ACTIVE",
				},
			},
		},
		policyRules: map[string][]okta.PolicyRule{
			"default-policy": {
				{
					ID:     "rule1",
					Status: "ACTIVE",
					Actions: okta.PolicyRuleActions{
						Signon: &okta.SignonActions{
							RequireFactor: false, // No MFA required
							Session: struct {
								UsePersistentCookie       bool `json:"usePersistentCookie"`
								MaxSessionIdleMinutes     int  `json:"maxSessionIdleMinutes"`
								MaxSessionLifetimeMinutes int  `json:"maxSessionLifetimeMinutes"`
							}{
								MaxSessionLifetimeMinutes: 1440, // 24 hours
								MaxSessionIdleMinutes:     120,  // 2 hours
							},
						},
					},
				},
			},
			"admins-policy": {
				{
					ID:     "rule2",
					Status: "ACTIVE",
					Actions: okta.PolicyRuleActions{
						Signon: &okta.SignonActions{
							RequireFactor: true, // MFA required
							Session: struct {
								UsePersistentCookie       bool `json:"usePersistentCookie"`
								MaxSessionIdleMinutes     int  `json:"maxSessionIdleMinutes"`
								MaxSessionLifetimeMinutes int  `json:"maxSessionLifetimeMinutes"`
							}{
								MaxSessionLifetimeMinutes: 15,  // 15 minutes
								MaxSessionIdleMinutes:     5,   // 5 minutes
							},
						},
					},
				},
			},
		},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.Policy.PolicyCount != 2 {
		t.Errorf("expected policy count 2, got %d", posture.Policy.PolicyCount)
	}

	// Only one policy requires MFA
	if posture.Policy.MFARequiredAll {
		t.Error("expected MFA required all to be false (only admins policy requires MFA)")
	}

	if !posture.Policy.MFARequiredAny {
		t.Error("expected MFA required any to be true (admins policy requires MFA)")
	}

	// Session lifetime: min=15 (admins), max=1440 (default)
	if posture.Policy.SessionLifetimeMinMinutes == nil || *posture.Policy.SessionLifetimeMinMinutes != 15 {
		t.Errorf("expected session lifetime min 15, got %v", posture.Policy.SessionLifetimeMinMinutes)
	}

	if posture.Policy.SessionLifetimeMaxMinutes == nil || *posture.Policy.SessionLifetimeMaxMinutes != 1440 {
		t.Errorf("expected session lifetime max 1440, got %v", posture.Policy.SessionLifetimeMaxMinutes)
	}

	// Idle timeout: min=5 (admins), max=120 (default)
	if posture.Policy.IdleTimeoutMinMinutes == nil || *posture.Policy.IdleTimeoutMinMinutes != 5 {
		t.Errorf("expected idle timeout min 5, got %v", posture.Policy.IdleTimeoutMinMinutes)
	}

	if posture.Policy.IdleTimeoutMaxMinutes == nil || *posture.Policy.IdleTimeoutMaxMinutes != 120 {
		t.Errorf("expected idle timeout max 120, got %v", posture.Policy.IdleTimeoutMaxMinutes)
	}
}

func TestCollect_MissingOrgDomain(t *testing.T) {
	client := &mockOktaClient{}
	c := NewWithClient(Config{OrgDomain: ""}, client)

	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error for missing org_domain")
	}
}

func TestPercent(t *testing.T) {
	tests := []struct {
		count    int
		total    int
		expected int
	}{
		{0, 0, 0},
		{0, 100, 0},
		{50, 100, 50},
		{1, 3, 33},
		{2, 3, 66},
		{100, 100, 100},
	}

	for _, tt := range tests {
		result := percent(tt.count, tt.total)
		if result != tt.expected {
			t.Errorf("percent(%d, %d) = %d, want %d", tt.count, tt.total, result, tt.expected)
		}
	}
}

func TestSchemaVersion(t *testing.T) {
	if SchemaVersion != "1.0.0" {
		t.Errorf("expected schema version 1.0.0, got %s", SchemaVersion)
	}
}

func TestNewOrgPosture(t *testing.T) {
	posture := NewOrgPosture("test.okta.com")

	if posture.SchemaVersion != SchemaVersion {
		t.Errorf("expected schema version %s, got %s", SchemaVersion, posture.SchemaVersion)
	}

	if posture.OrgDomain != "test.okta.com" {
		t.Errorf("expected org domain test.okta.com, got %s", posture.OrgDomain)
	}

	if posture.CollectedAt == "" {
		t.Error("expected collected_at to be set")
	}

	// Verify it's valid RFC3339
	_, err := time.Parse(time.RFC3339, posture.CollectedAt)
	if err != nil {
		t.Errorf("collected_at is not valid RFC3339: %v", err)
	}
}

func TestOutputJSONStructure(t *testing.T) {
	client := &mockOktaClient{
		users:    []okta.User{},
		factors:  make(map[string][]okta.Factor),
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Serialize to JSON to verify structure
	data, err := json.MarshalIndent(posture, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal posture: %v", err)
	}

	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check required top-level fields
	requiredFields := []string{"schema_version", "collected_at", "org_domain", "posture", "users", "apps", "policy"}
	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}
}

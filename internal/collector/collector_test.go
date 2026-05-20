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

// mockOktaClient implements okta.OktaClient for testing.
type mockOktaClient struct {
	users                      []okta.User
	usersErr                   error
	factors                    map[string][]okta.Factor // userID -> factors
	factorsErr                 error
	groupUsers                 map[string][]okta.User // groupID -> users
	groupUsersErr              error
	roleAssignees              []okta.RoleAssignedUser
	roleAssigneesErr           error
	userRoles                  map[string][]okta.RoleAssignment
	userRolesErr               error
	userGroupIDs               map[string][]string
	userGroupIDsErr            error
	apps                       []okta.Application
	appsErr                    error
	policies                   map[string][]okta.Policy // policyType -> policies
	policiesErr                error
	policyRules                map[string][]okta.PolicyRule // policyID -> rules
	rulesErr                   error
	deviceAssurancePolicies    []okta.DeviceAssurancePolicy
	deviceAssurancePoliciesErr error
	authenticators             []okta.Authenticator
	authenticatorsErr          error
	groups                     []okta.Group
	groupsErr                  error
	iamRoles                   []okta.IAMRole
	iamRolesErr                error
	rolePermissions            map[string][]string
	rolePermissionsErr         error
	networkZones               []okta.NetworkZone
	networkZonesErr            error
	identityProviders          []okta.IdentityProvider
	identityProvidersErr       error
	apiTokens                  []okta.APIToken
	apiTokensErr               error
	eventHooks                 []okta.EventHook
	eventHooksErr              error
	inlineHooks                []okta.InlineHook
	inlineHooksErr             error
	systemLog                  []okta.LogEvent
	systemLogErr               error
	orgSettings                *okta.OrgSettings
	orgErr                     error
	orgPreferences             *okta.OrgPreferences
	orgPreferencesErr          error
	orgContacts                []okta.OrgContact
	orgContactsErr             error
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

func (m *mockOktaClient) FetchGroupUsers(ctx context.Context, groupID string, callback func([]okta.User) error) error {
	if m.groupUsersErr != nil {
		return m.groupUsersErr
	}
	return callback(m.groupUsers[groupID])
}

func (m *mockOktaClient) FetchUsersWithRoleAssignments(ctx context.Context, callback func([]okta.RoleAssignedUser) error) error {
	if m.roleAssigneesErr != nil {
		return m.roleAssigneesErr
	}
	return callback(m.roleAssignees)
}

func (m *mockOktaClient) FetchUserRoleAssignments(ctx context.Context, userID string) ([]okta.RoleAssignment, error) {
	if m.userRolesErr != nil {
		return nil, m.userRolesErr
	}
	return m.userRoles[userID], nil
}

func (m *mockOktaClient) FetchUserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	if m.userGroupIDsErr != nil {
		return nil, m.userGroupIDsErr
	}
	return m.userGroupIDs[userID], nil
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

func (m *mockOktaClient) FetchDeviceAssurancePolicies(ctx context.Context) ([]okta.DeviceAssurancePolicy, error) {
	if m.deviceAssurancePoliciesErr != nil {
		return nil, m.deviceAssurancePoliciesErr
	}
	return m.deviceAssurancePolicies, nil
}

func (m *mockOktaClient) ListIAMRoles(ctx context.Context) ([]okta.IAMRole, error) {
	if m.iamRolesErr != nil {
		return nil, m.iamRolesErr
	}
	return m.iamRoles, nil
}

func (m *mockOktaClient) ListRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	if m.rolePermissionsErr != nil {
		return nil, m.rolePermissionsErr
	}
	return m.rolePermissions[roleID], nil
}

func (m *mockOktaClient) ListGroups(ctx context.Context, callback func([]okta.Group) error) error {
	if m.groupsErr != nil {
		return m.groupsErr
	}
	return callback(m.groups)
}

func (m *mockOktaClient) ListAuthenticators(ctx context.Context) ([]okta.Authenticator, error) {
	if m.authenticatorsErr != nil {
		return nil, m.authenticatorsErr
	}
	return m.authenticators, nil
}

func (m *mockOktaClient) FetchOrgSettings(ctx context.Context) (*okta.OrgSettings, error) {
	if m.orgErr != nil {
		return nil, m.orgErr
	}
	return m.orgSettings, nil
}

func (m *mockOktaClient) ListNetworkZones(ctx context.Context) ([]okta.NetworkZone, error) {
	return m.networkZones, m.networkZonesErr
}

func (m *mockOktaClient) ListIdentityProviders(ctx context.Context) ([]okta.IdentityProvider, error) {
	return m.identityProviders, m.identityProvidersErr
}

func (m *mockOktaClient) ListAPITokens(ctx context.Context) ([]okta.APIToken, error) {
	return m.apiTokens, m.apiTokensErr
}

func (m *mockOktaClient) ListEventHooks(ctx context.Context) ([]okta.EventHook, error) {
	return m.eventHooks, m.eventHooksErr
}

func (m *mockOktaClient) ListInlineHooks(ctx context.Context) ([]okta.InlineHook, error) {
	return m.inlineHooks, m.inlineHooksErr
}

func (m *mockOktaClient) ListSystemLog(ctx context.Context, filter string, since time.Time, max int) ([]okta.LogEvent, error) {
	if m.systemLogErr != nil {
		return nil, m.systemLogErr
	}
	events := m.systemLog
	if len(events) > max {
		events = events[:max]
	}
	return events, nil
}

func (m *mockOktaClient) FetchOrgPreferences(ctx context.Context) (*okta.OrgPreferences, error) {
	return m.orgPreferences, m.orgPreferencesErr
}

func (m *mockOktaClient) FetchOrgContactUsers(ctx context.Context) ([]okta.OrgContact, error) {
	return m.orgContacts, m.orgContactsErr
}

func TestCollect_EmptyOrganization(t *testing.T) {
	client := &mockOktaClient{
		users:    []okta.User{},
		factors:  make(map[string][]okta.Factor),
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)

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
			{ID: "user6", Status: "SUSPENDED", LastLogin: recentLogin},
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
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3 users with MFA (user1, user2, user4) out of 5
	// MFA coverage = 60%
	if posture.Posture.MFACoverage != 60 {
		t.Errorf("expected 60%% MFA coverage, got %d%%", posture.Posture.MFACoverage)
	}

	// Only user4 has phishing-resistant MFA (webauthn) = 20%
	if posture.Posture.MFAPhishingResistant != 20 {
		t.Errorf("expected 20%% phishing resistant, got %d%%", posture.Posture.MFAPhishingResistant)
	}

	// 1 user locked out = 20%
	if posture.Users.LockedOut != 20 {
		t.Errorf("expected 20%% locked out, got %d%%", posture.Users.LockedOut)
	}

	// 1 user inactive (user3) = 20%
	if posture.Users.Inactive != 20 {
		t.Errorf("expected 20%% inactive, got %d%%", posture.Users.Inactive)
	}

	// 1 user suspended (user6) = 20%
	if posture.Users.Suspended != 20 {
		t.Errorf("expected 20%% suspended, got %d%%", posture.Users.Suspended)
	}
}

func TestCollect_WithPrivilegedAccess(t *testing.T) {
	now := time.Now()
	recentLogin := now.AddDate(0, 0, -7)

	client := &mockOktaClient{
		users: []okta.User{
			{ID: "admin1", Status: "ACTIVE", LastLogin: recentLogin},
			{ID: "admin2", Status: "ACTIVE", LastLogin: recentLogin},
			{ID: "suspended-admin", Status: "SUSPENDED", LastLogin: recentLogin},
			{ID: "deprov-admin", Status: "DEPROVISIONED", LastLogin: recentLogin},
			{ID: "user1", Status: "ACTIVE", LastLogin: recentLogin},
		},
		factors: map[string][]okta.Factor{
			"admin1":          {{ID: "f1", FactorType: "push", Status: "ACTIVE"}},
			"admin2":          {{ID: "f2", FactorType: "webauthn", Status: "ACTIVE"}},
			"suspended-admin": {{ID: "f3", FactorType: "webauthn", Status: "ACTIVE"}},
			"deprov-admin":    {{ID: "f4", FactorType: "webauthn", Status: "ACTIVE"}},
			"user1":           {{ID: "f5", FactorType: "push", Status: "ACTIVE"}},
		},
		roleAssignees: []okta.RoleAssignedUser{
			{ID: "admin1"},
			{ID: "admin2"},
			{ID: "suspended-admin"},
			{ID: "deprov-admin"},
		},
		userRoles: map[string][]okta.RoleAssignment{
			"admin1":          {{ID: "r1", Type: "USER_ADMIN"}},
			"admin2":          {{ID: "r2", Type: "SUPER_ADMIN"}},
			"suspended-admin": {{ID: "r3", Type: "ORG_ADMIN"}},
			"deprov-admin":    {{ID: "r4", Type: "SUPER_ADMIN"}},
		},
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.PrivilegedAccess.PrivilegedUsersCount != 2 {
		t.Fatalf("expected 2 privileged users, got %d", posture.PrivilegedAccess.PrivilegedUsersCount)
	}
	if posture.PrivilegedAccess.SuperAdminCount != 1 {
		t.Fatalf("expected 1 super admin, got %d", posture.PrivilegedAccess.SuperAdminCount)
	}
	if posture.PrivilegedAccess.StandingPrivilegedUsersCount != 2 {
		t.Fatalf("expected 2 standing privileged users, got %d", posture.PrivilegedAccess.StandingPrivilegedUsersCount)
	}
	if posture.PrivilegedAccess.PrivilegedMFACoveragePct != 100 {
		t.Fatalf("expected 100%% privileged MFA coverage, got %d%%", posture.PrivilegedAccess.PrivilegedMFACoveragePct)
	}
	if posture.PrivilegedAccess.PrivilegedPhishingResistantPct != 50 {
		t.Fatalf("expected 50%% privileged phishing-resistant coverage, got %d%%", posture.PrivilegedAccess.PrivilegedPhishingResistantPct)
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
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)

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
		users: []okta.User{
			{ID: "user1", Status: "ACTIVE", LastLogin: time.Now()},
		},
		factors: make(map[string][]okta.Factor),
		apps:    []okta.Application{},
		policies: map[string][]okta.Policy{
			"OKTA_SIGN_ON": {
				{
					ID:       "policy1",
					Status:   "ACTIVE",
					Priority: 1,
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
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)

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

	if posture.Policy.MFARequiredCoveragePct != 100 {
		t.Errorf("expected MFA required coverage 100%%, got %d%%", posture.Policy.MFARequiredCoveragePct)
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
		users: []okta.User{
			{ID: "admin1", Status: "ACTIVE", LastLogin: time.Now()},
			{ID: "user1", Status: "ACTIVE", LastLogin: time.Now()},
			{ID: "user2", Status: "ACTIVE", LastLogin: time.Now()},
		},
		factors: make(map[string][]okta.Factor),
		apps:    []okta.Application{},
		groupUsers: map[string][]okta.User{
			"grp-admins": {
				{ID: "admin1"},
			},
		},
		policies: map[string][]okta.Policy{
			"OKTA_SIGN_ON": {
				{
					ID:       "admins-policy",
					Status:   "ACTIVE",
					Priority: 1,
					Conditions: okta.PolicyConditions{
						People: &okta.PolicyPeopleCondition{
							Groups: &struct {
								Include []string `json:"include,omitempty"`
								Exclude []string `json:"exclude,omitempty"`
							}{
								Include: []string{"grp-admins"},
							},
						},
					},
				},
				{
					ID:       "default-policy",
					Status:   "ACTIVE",
					Priority: 2,
				},
			},
		},
		policyRules: map[string][]okta.PolicyRule{
			"admins-policy": {
				{
					ID:       "rule2",
					Status:   "ACTIVE",
					Priority: 1,
					Actions: okta.PolicyRuleActions{
						Signon: &okta.SignonActions{
							RequireFactor: true, // MFA required
							Session: struct {
								UsePersistentCookie       bool `json:"usePersistentCookie"`
								MaxSessionIdleMinutes     int  `json:"maxSessionIdleMinutes"`
								MaxSessionLifetimeMinutes int  `json:"maxSessionLifetimeMinutes"`
							}{
								MaxSessionLifetimeMinutes: 15, // 15 minutes
								MaxSessionIdleMinutes:     5,  // 5 minutes
							},
						},
					},
				},
			},
			"default-policy": {
				{
					ID:       "rule1",
					Status:   "ACTIVE",
					Priority: 1,
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
		},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)

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

	if posture.Policy.MFARequiredCoveragePct != 33 {
		t.Errorf("expected MFA required coverage 33%%, got %d%%", posture.Policy.MFARequiredCoveragePct)
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

func TestCollect_TrustOmitsAuditFields(t *testing.T) {
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "user1", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "user1@acme.com"}},
		},
		factors: map[string][]okta.Factor{
			"user1": {{ID: "f1", FactorType: "push", Status: "ACTIVE"}},
		},
		apps: []okta.Application{
			{ID: "app1", Label: "App One", Name: "app_one", SignOnMode: "SAML_2_0", Status: "ACTIVE"},
		},
		policies: make(map[string][]okta.Policy),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.CollectedAtLevel != "trust" {
		t.Errorf("expected collected_at_level=trust, got %q", posture.CollectedAtLevel)
	}
	if posture.Users.Inventory != nil {
		t.Errorf("expected nil user inventory at trust, got %v", posture.Users.Inventory)
	}
	if posture.Apps.Inventory != nil {
		t.Errorf("expected nil app inventory at trust, got %v", posture.Apps.Inventory)
	}
	if posture.Posture.PerFactorType != nil {
		t.Errorf("expected nil per_factor_type at trust, got %v", posture.Posture.PerFactorType)
	}
	if posture.Posture.MFADisabledUsersCount != nil {
		t.Errorf("expected nil mfa_disabled_users_count at trust, got %v", posture.Posture.MFADisabledUsersCount)
	}
}

func TestCollect_AuditInventory(t *testing.T) {
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "human@acme.com", UserType: "Employee"}},
			{ID: "u2", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "svc-ci@acme.com", UserType: "Service Account"}},
		},
		factors: map[string][]okta.Factor{
			"u1": {{ID: "f1", FactorType: "webauthn", Status: "ACTIVE"}},
			"u2": {{ID: "f2", FactorType: "push", Status: "ACTIVE"}},
		},
		apps: []okta.Application{
			{ID: "app1", Label: "SAML App", Name: "saml_app", SignOnMode: "SAML_2_0", Status: "ACTIVE", Features: []string{"PUSH_NEW_USERS"}},
			{ID: "app2", Label: "SWA App", Name: "swa_app", SignOnMode: "BROWSER_PLUGIN", Status: "ACTIVE"},
		},
		policies: make(map[string][]okta.Policy),
		authenticators: []okta.Authenticator{
			{Key: "okta_email", Status: "ACTIVE"}, // enabled but unenrolled -> zero-count seed
		},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.CollectedAtLevel != "audit" {
		t.Errorf("expected collected_at_level=audit, got %q", posture.CollectedAtLevel)
	}

	if len(posture.Users.Inventory) != 2 {
		t.Fatalf("expected 2 user inventory rows, got %d", len(posture.Users.Inventory))
	}
	byLogin := map[string]User{}
	for _, u := range posture.Users.Inventory {
		byLogin[u.Login] = u
	}
	if byLogin["human@acme.com"].UserType != "Human" {
		t.Errorf("expected Human, got %q", byLogin["human@acme.com"].UserType)
	}
	if byLogin["svc-ci@acme.com"].UserType != "Service" {
		t.Errorf("expected Service, got %q", byLogin["svc-ci@acme.com"].UserType)
	}

	if len(posture.Apps.Inventory) != 2 {
		t.Fatalf("expected 2 app inventory rows, got %d", len(posture.Apps.Inventory))
	}
	for _, a := range posture.Apps.Inventory {
		switch a.Name {
		case "saml_app":
			if a.Type != "SAML" || !a.SSOConfigured || !a.ProvisioningConfigured {
				t.Errorf("saml_app row wrong: %+v", a)
			}
		case "swa_app":
			if a.Type != "SWA" || a.SSOConfigured {
				t.Errorf("swa_app row wrong: %+v", a)
			}
		}
	}

	// Per-factor-type: push (1), webauthn (1), and email seeded at 0 from catalog.
	counts := map[string]int{}
	for _, ftc := range posture.Posture.PerFactorType {
		counts[ftc.FactorType] = ftc.EnrolledUsers
	}
	if counts["push"] != 1 || counts["webauthn"] != 1 {
		t.Errorf("expected push=1 webauthn=1, got %v", counts)
	}
	if v, ok := counts["email"]; !ok || v != 0 {
		t.Errorf("expected email seeded at 0 from catalog, got %v (present=%v)", v, ok)
	}
	if posture.Posture.MFADisabledUsersCount == nil || *posture.Posture.MFADisabledUsersCount != 0 {
		t.Errorf("expected mfa_disabled_users_count=0, got %v", posture.Posture.MFADisabledUsersCount)
	}
}

func TestCollect_AuditPrivilegedAndPolicy(t *testing.T) {
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "admin1", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "admin1@acme.com"}},
			{ID: "user1", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "user1@acme.com"}},
		},
		factors:       make(map[string][]okta.Factor),
		apps:          []okta.Application{},
		roleAssignees: []okta.RoleAssignedUser{{ID: "admin1"}},
		userRoles: map[string][]okta.RoleAssignment{
			"admin1": {{ID: "r1", Type: "SUPER_ADMIN"}, {ID: "r2", Type: "CUSTOM", Label: "Billing Admin"}},
		},
		policies: map[string][]okta.Policy{
			"OKTA_SIGN_ON": {
				{ID: "p1", Name: "Default Sign-on", Type: "OKTA_SIGN_ON", Status: "ACTIVE", Priority: 1},
			},
		},
		policyRules: map[string][]okta.PolicyRule{
			"p1": {{ID: "rule1", Status: "ACTIVE", Actions: okta.PolicyRuleActions{Signon: &okta.SignonActions{RequireFactor: true}}}},
		},
		iamRoles: []okta.IAMRole{
			{ID: "cr1", Label: "Billing Admin", Description: "manages billing"},
		},
		rolePermissions: map[string][]string{
			"cr1": {"okta.users.read", "okta.apps.read"},
		},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(posture.PrivilegedAccess.Inventory) != 1 {
		t.Fatalf("expected 1 privileged inventory row, got %d", len(posture.PrivilegedAccess.Inventory))
	}
	row := posture.PrivilegedAccess.Inventory[0]
	if row.Login != "admin1@acme.com" || len(row.Roles) != 2 || row.Roles[0] != "SUPER_ADMIN" || row.Roles[1] != "Billing Admin" {
		t.Errorf("privileged inventory row wrong: %+v", row)
	}

	if len(posture.PrivilegedAccess.CustomRoles) != 1 {
		t.Fatalf("expected 1 custom role, got %d", len(posture.PrivilegedAccess.CustomRoles))
	}
	cr := posture.PrivilegedAccess.CustomRoles[0]
	if cr.Label != "Billing Admin" || cr.PermissionCount != 2 {
		t.Errorf("custom role wrong: %+v", cr)
	}

	if len(posture.Policy.Policies) != 1 {
		t.Fatalf("expected 1 policy summary, got %d", len(posture.Policy.Policies))
	}
	ps := posture.Policy.Policies[0]
	if ps.Name != "Default Sign-on" || ps.RuleCount != 1 || ps.ScopeSummary != "everyone" {
		t.Errorf("policy summary wrong: %+v", ps)
	}
}

func TestPrivileged_DegradesOnNonIdentityGovernance(t *testing.T) {
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "admin1", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "admin1@acme.com"}},
		},
		factors:       make(map[string][]okta.Factor),
		apps:          []okta.Application{},
		roleAssignees: []okta.RoleAssignedUser{{ID: "admin1"}},
		userRoles: map[string][]okta.RoleAssignment{
			"admin1": {{ID: "r1", Type: "SUPER_ADMIN"}},
		},
		policies:    make(map[string][]okta.Policy),
		iamRolesErr: &okta.APIStatusError{StatusCode: 404, Path: "/api/v1/iam/roles"},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}

	// Built-in roles still surface in the inventory.
	if len(posture.PrivilegedAccess.Inventory) != 1 {
		t.Errorf("expected built-in role inventory to survive, got %d rows", len(posture.PrivilegedAccess.Inventory))
	}
	// Custom roles normalize to [] (collected, none available).
	if posture.PrivilegedAccess.CustomRoles == nil {
		t.Error("expected non-nil custom_roles at audit (normalized)")
	}
	// A diagnostic explains why custom roles are absent.
	if posture.Diagnostics == nil {
		t.Fatal("expected diagnostics for IG-not-licensed degradation")
	}
	found := false
	for _, w := range posture.Diagnostics.Warnings {
		if strings.Contains(w, "Identity Governance") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an Identity Governance diagnostic, got %v", posture.Diagnostics.Warnings)
	}
}

func TestPrivileged_DegradesOnAssigneesForbidden(t *testing.T) {
	// A least-privilege (Read-Only Administrator) service app gets a 403 listing
	// admin-role assignments. The run must still succeed with the other surfaces,
	// emitting zeroed privileged metrics plus a diagnostic.
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "user1", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "user1@acme.com"}},
		},
		factors:          map[string][]okta.Factor{"user1": {{ID: "f1", FactorType: "webauthn", Status: "ACTIVE"}}},
		apps:             []okta.Application{{ID: "app1", SignOnMode: "SAML_2_0", Status: "ACTIVE"}},
		policies:         make(map[string][]okta.Policy),
		roleAssigneesErr: &okta.APIStatusError{StatusCode: 403, Path: "/api/v1/iam/assignees/users"},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}

	// Other surfaces still collected.
	if posture.Posture.MFACoverage != 100 {
		t.Errorf("expected MFA coverage to be collected despite privileged 403, got %d", posture.Posture.MFACoverage)
	}
	// Privileged metrics degrade to zero (not collected).
	if posture.PrivilegedAccess.PrivilegedUsersCount != 0 {
		t.Errorf("expected zero privileged users on 403, got %d", posture.PrivilegedAccess.PrivilegedUsersCount)
	}
	// A diagnostic explains the 403.
	if posture.Diagnostics == nil {
		t.Fatal("expected diagnostics for privileged-access 403")
	}
	found := false
	for _, w := range posture.Diagnostics.Warnings {
		if strings.Contains(w, "admin-role assignments") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a privileged-access 403 diagnostic, got %v", posture.Diagnostics.Warnings)
	}
}

func TestCoreSurfaces_DegradeOnForbidden(t *testing.T) {
	// Every core surface returns 403 (a maximally locked-down service app). The
	// run must still succeed, emitting zeroed core metrics and a diagnostic per
	// skipped surface rather than failing outright.
	forbidden := func(path string) error { return &okta.APIStatusError{StatusCode: 403, Path: path} }
	client := &mockOktaClient{
		usersErr:                   forbidden("/api/v1/users"),
		appsErr:                    forbidden("/api/v1/apps"),
		policiesErr:                forbidden("/api/v1/policies"),
		deviceAssurancePoliciesErr: forbidden("/api/v1/device-assurances"),
		roleAssigneesErr:           forbidden("/api/v1/iam/assignees/users"),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("expected degraded success, got error: %v", err)
	}

	if posture.Posture.MFACoverage != 0 || posture.Apps.ProvisioningEnabled != 0 ||
		posture.PrivilegedAccess.PrivilegedUsersCount != 0 || posture.Policy.PolicyCount != 0 ||
		posture.DeviceAccess.DeviceAssurancePoliciesCount != 0 {
		t.Error("expected all core metrics to degrade to zero")
	}
	if posture.Diagnostics == nil || len(posture.Diagnostics.Warnings) < 4 {
		t.Fatalf("expected a diagnostic per skipped surface, got %+v", posture.Diagnostics)
	}
}

func TestCollect_AuditDeviceAssurance(t *testing.T) {
	trueVal := true
	client := &mockOktaClient{
		users:    []okta.User{},
		factors:  make(map[string][]okta.Factor),
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
		deviceAssurancePolicies: []okta.DeviceAssurancePolicy{
			{
				ID: "dap1", Name: "iOS Baseline", Platform: "IOS", Status: "ACTIVE",
				OSVersion: &struct {
					Minimum string `json:"minimum"`
				}{Minimum: "17.0"},
				DiskEncryptionType: &struct {
					Include []string `json:"include"`
				}{Include: []string{"FULL"}},
				ScreenLockType: &struct {
					Include []string `json:"include"`
				}{Include: []string{"BIOMETRIC"}},
				Jailbreak: &trueVal,
			},
		},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(posture.DeviceAccess.Policies) != 1 {
		t.Fatalf("expected 1 device assurance summary, got %d", len(posture.DeviceAccess.Policies))
	}
	d := posture.DeviceAccess.Policies[0]
	if d.Name != "iOS Baseline" || d.Platform != "IOS" || d.MinOSVersion != "17.0" {
		t.Errorf("device summary wrong: %+v", d)
	}
	if !d.DiskEncryptionReq || !d.ScreenLockReq || !d.JailbreakProtection {
		t.Errorf("expected requirement flags set: %+v", d)
	}
}

func TestCollect_InternalDetails(t *testing.T) {
	now := time.Now()
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "admin1", Status: "ACTIVE", LastLogin: now, LastUpdated: now, Created: now, Profile: okta.UserProfile{Login: "admin1@acme.com"}},
		},
		factors: map[string][]okta.Factor{
			"admin1": {{ID: "f1", FactorType: "webauthn", Status: "ACTIVE", Created: now}},
		},
		userGroupIDs: map[string][]string{
			"admin1": {"grp-1", "grp-2"},
		},
		apps:          []okta.Application{},
		roleAssignees: []okta.RoleAssignedUser{{ID: "admin1"}},
		userRoles: map[string][]okta.RoleAssignment{
			"admin1": {{ID: "r1", Type: "SUPER_ADMIN", AssignmentType: "GROUP"}},
		},
		policies: map[string][]okta.Policy{
			"OKTA_SIGN_ON": {{ID: "p1", Name: "Default", Type: "OKTA_SIGN_ON", Status: "ACTIVE", Priority: 1}},
		},
		policyRules: map[string][]okta.PolicyRule{
			"p1": {{
				ID: "rule1", Name: "Require MFA", Status: "ACTIVE", Priority: 1,
				Actions: okta.PolicyRuleActions{Signon: &okta.SignonActions{Access: "ALLOW", RequireFactor: true}},
			}},
		},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.CollectedAtLevel != "internal" {
		t.Errorf("expected collected_at_level=internal, got %q", posture.CollectedAtLevel)
	}

	if len(posture.Users.Inventory) != 1 {
		t.Fatalf("expected 1 user, got %d", len(posture.Users.Inventory))
	}
	u := posture.Users.Inventory[0]
	if u.LastLoginAt == "" || u.LastUpdatedAt == "" {
		t.Errorf("expected internal timestamps, got %+v", u)
	}
	if len(u.Factors) != 1 || u.Factors[0].FactorType != "webauthn" || u.Factors[0].EnrolledAt == "" {
		t.Errorf("expected webauthn factor with enrolled_at, got %+v", u.Factors)
	}
	if len(u.GroupIDs) != 2 {
		t.Errorf("expected 2 group IDs, got %v", u.GroupIDs)
	}

	if len(posture.PrivilegedAccess.Inventory) != 1 {
		t.Fatalf("expected 1 privileged user, got %d", len(posture.PrivilegedAccess.Inventory))
	}
	pu := posture.PrivilegedAccess.Inventory[0]
	if pu.RoleAssignmentSource != "group" || pu.LastLoginAt == "" {
		t.Errorf("expected group source + last login, got %+v", pu)
	}

	if len(posture.Policy.Policies) != 1 || len(posture.Policy.Policies[0].Rules) != 1 {
		t.Fatalf("expected 1 policy with 1 rule detail, got %+v", posture.Policy.Policies)
	}
	rule := posture.Policy.Policies[0].Rules[0]
	if rule.Name != "Require MFA" || rule.Access != "ALLOW" || rule.RequireFactor == nil || !*rule.RequireFactor {
		t.Errorf("rule detail wrong: %+v", rule)
	}
}

func TestPhishingResistant_CountsFastPass(t *testing.T) {
	// Okta FastPass enrolls as the "signed_nonce" factor type and is
	// phishing-resistant, like WebAuthn.
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "u1@acme.com"}},
			{ID: "u2", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "u2@acme.com"}},
		},
		factors: map[string][]okta.Factor{
			"u1": {{ID: "f1", FactorType: "signed_nonce", Status: "ACTIVE"}},
			"u2": {{ID: "f2", FactorType: "token:software:totp", Status: "ACTIVE"}},
		},
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// u1 (FastPass) counts as phishing-resistant; u2 (TOTP) does not = 50%.
	if posture.Posture.MFAPhishingResistant != 50 {
		t.Errorf("expected 50%% phishing-resistant (FastPass counts), got %d", posture.Posture.MFAPhishingResistant)
	}
}

func TestNetworkZones_WarnsOnUnexpectedShape(t *testing.T) {
	client := &mockOktaClient{
		users:    []okta.User{},
		factors:  make(map[string][]okta.Factor),
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
		networkZones: []okta.NetworkZone{
			// Empty object for locations/asns is treated as empty (no warning);
			// a populated but wrong shape for gateways must warn.
			{ID: "z1", Name: "Weird", Type: "IP", Status: "ACTIVE", Usage: "POLICY",
				Gateways:  json.RawMessage(`{"unexpected":"object"}`),
				Locations: json.RawMessage(`{}`)},
		},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.Diagnostics == nil {
		t.Fatal("expected a diagnostic for the unexpected gateways shape")
	}
	found := false
	for _, w := range posture.Diagnostics.Warnings {
		if strings.Contains(w, `zone "Weird" gateways: unexpected shape`) {
			found = true
		}
		if strings.Contains(w, "locations") {
			t.Errorf("empty-object locations must not warn, got %q", w)
		}
	}
	if !found {
		t.Errorf("expected a gateways shape-mismatch diagnostic, got %v", posture.Diagnostics.Warnings)
	}
}

func TestCollect_MissingOrgDomain(t *testing.T) {
	client := &mockOktaClient{}
	c := NewWithClient(Config{OrgDomain: ""}, client)

	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
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
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
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
	requiredFields := []string{"schema_version", "collected_at", "org_domain", "posture", "users", "apps", "privileged_access", "policy", "device_access"}
	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}
}

func intPtr(i int) *int {
	return &i
}

func TestToIDPPosture(t *testing.T) {
	// Test transformation from OrgPosture to normalized IDPPosture
	orgPosture := &OrgPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   "2024-01-15T10:00:00Z",
		OrgDomain:     "acme.okta.com",
		Posture: Posture{
			MFACoverage:          95,
			MFAPhishingResistant: 40,
			SSOCoverage:          85,
		},
		Users: UserMetrics{
			PasswordExpired: 5,
			LockedOut:       2,
			Inactive:        8,
			Suspended:       7,
		},
		Apps: AppMetrics{
			ProvisioningEnabled:   60,
			DeprovisioningEnabled: 45,
		},
		PrivilegedAccess: PrivilegedAccessMetrics{
			PrivilegedUsersCount:           3,
			SuperAdminCount:                1,
			StandingPrivilegedUsersCount:   3,
			PrivilegedMFACoveragePct:       67,
			PrivilegedPhishingResistantPct: 33,
		},
		Policy: PolicyConfig{
			PolicyCount:               3,
			MFARequiredAll:            false,
			MFARequiredAny:            true,
			MFARequiredCoveragePct:    66,
			SessionLifetimeMinMinutes: intPtr(15),
			SessionLifetimeMaxMinutes: intPtr(1440),
			IdleTimeoutMinMinutes:     intPtr(5),
			IdleTimeoutMaxMinutes:     intPtr(120),
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	// Verify basic fields
	if idpPosture.SchemaVersion != "1.0.0" {
		t.Errorf("SchemaVersion = %q, want %q", idpPosture.SchemaVersion, "1.0.0")
	}
	if idpPosture.Provider != "okta" {
		t.Errorf("Provider = %q, want %q", idpPosture.Provider, "okta")
	}
	if idpPosture.OrgDomain != "acme.okta.com" {
		t.Errorf("OrgDomain = %q, want %q", idpPosture.OrgDomain, "acme.okta.com")
	}

	// Verify user_security mappings
	if idpPosture.UserSecurity.MFACoveragePct != 95 {
		t.Errorf("UserSecurity.MFACoveragePct = %v, want 95", idpPosture.UserSecurity.MFACoveragePct)
	}
	if idpPosture.UserSecurity.MFAPhishingResistantPct != 40 {
		t.Errorf("UserSecurity.MFAPhishingResistantPct = %v, want 40", idpPosture.UserSecurity.MFAPhishingResistantPct)
	}
	if idpPosture.UserSecurity.InactivePct != 8 {
		t.Errorf("UserSecurity.InactivePct = %v, want 8", idpPosture.UserSecurity.InactivePct)
	}
	if idpPosture.UserSecurity.LockedOutPct != 2 {
		t.Errorf("UserSecurity.LockedOutPct = %v, want 2", idpPosture.UserSecurity.LockedOutPct)
	}
	if idpPosture.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want non-nil")
	}
	if idpPosture.Lifecycle.SuspendedPct == nil || *idpPosture.Lifecycle.SuspendedPct != 7 {
		t.Fatalf("Lifecycle.SuspendedPct = %v, want 7", idpPosture.Lifecycle.SuspendedPct)
	}
	if idpPosture.PrivilegedAccess == nil {
		t.Fatal("PrivilegedAccess = nil, want non-nil")
	}
	if idpPosture.PrivilegedAccess.PrivilegedUsersCount != 3 {
		t.Fatalf("PrivilegedUsersCount = %d, want 3", idpPosture.PrivilegedAccess.PrivilegedUsersCount)
	}
	if idpPosture.PrivilegedAccess.SuperAdminCount != 1 {
		t.Fatalf("SuperAdminCount = %d, want 1", idpPosture.PrivilegedAccess.SuperAdminCount)
	}
	if idpPosture.PrivilegedAccess.StandingPrivilegedUsersCount == nil || *idpPosture.PrivilegedAccess.StandingPrivilegedUsersCount != 3 {
		t.Fatalf("StandingPrivilegedUsersCount = %v, want 3", idpPosture.PrivilegedAccess.StandingPrivilegedUsersCount)
	}
	if idpPosture.PrivilegedAccess.PrivilegedMFACoveragePct == nil || *idpPosture.PrivilegedAccess.PrivilegedMFACoveragePct != 67 {
		t.Fatalf("PrivilegedMFACoveragePct = %v, want 67", idpPosture.PrivilegedAccess.PrivilegedMFACoveragePct)
	}
	if idpPosture.PrivilegedAccess.PrivilegedPhishingResistantPct == nil || *idpPosture.PrivilegedAccess.PrivilegedPhishingResistantPct != 33 {
		t.Fatalf("PrivilegedPhishingResistantPct = %v, want 33", idpPosture.PrivilegedAccess.PrivilegedPhishingResistantPct)
	}

	// Verify app_security mappings
	if idpPosture.AppSecurity == nil {
		t.Fatal("AppSecurity = nil, want non-nil")
	}
	if idpPosture.AppSecurity.SSOCoveragePct != 85 {
		t.Errorf("AppSecurity.SSOCoveragePct = %v, want 85", idpPosture.AppSecurity.SSOCoveragePct)
	}
	if idpPosture.AppSecurity.ProvisioningEnabledPct != 60 {
		t.Errorf("AppSecurity.ProvisioningEnabledPct = %v, want 60", idpPosture.AppSecurity.ProvisioningEnabledPct)
	}
	if idpPosture.AppSecurity.DeprovisioningEnabledPct != 45 {
		t.Errorf("AppSecurity.DeprovisioningEnabledPct = %v, want 45", idpPosture.AppSecurity.DeprovisioningEnabledPct)
	}

	// Verify policy mappings
	if idpPosture.Policy == nil {
		t.Fatal("Policy = nil, want non-nil")
	}
	if idpPosture.Policy.MFARequired {
		t.Error("Policy.MFARequired = true, want false when MFA is not required for all policies")
	}
	if idpPosture.Policy.MFARequiredCoveragePct == nil || *idpPosture.Policy.MFARequiredCoveragePct != 66 {
		t.Fatalf("Policy.MFARequiredCoveragePct = %v, want 66", idpPosture.Policy.MFARequiredCoveragePct)
	}
	if idpPosture.Policy.SessionLifetimeMaxMin == nil || *idpPosture.Policy.SessionLifetimeMaxMin != 1440 {
		t.Fatalf("Policy.SessionLifetimeMaxMin = %v, want 1440", idpPosture.Policy.SessionLifetimeMaxMin)
	}
	if idpPosture.Policy.IdleTimeoutMaxMin == nil || *idpPosture.Policy.IdleTimeoutMaxMin != 120 {
		t.Fatalf("Policy.IdleTimeoutMaxMin = %v, want 120", idpPosture.Policy.IdleTimeoutMaxMin)
	}
}

func TestToIDPPosture_MFARequiredAll(t *testing.T) {
	// Test that MFARequired is true when MFARequiredAll is true
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		Policy: PolicyConfig{
			MFARequiredAll:         true,
			MFARequiredAny:         true,
			MFARequiredCoveragePct: 100,
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	if !idpPosture.Policy.MFARequired {
		t.Error("Policy.MFARequired = false, want true (MFARequiredAll is true)")
	}
	if idpPosture.Policy.MFARequiredCoveragePct == nil || *idpPosture.Policy.MFARequiredCoveragePct != 100 {
		t.Fatalf("Policy.MFARequiredCoveragePct = %v, want 100", idpPosture.Policy.MFARequiredCoveragePct)
	}
}

func TestToIDPPosture_NoMFARequired(t *testing.T) {
	// Test that MFARequired is false when neither MFARequiredAll nor MFARequiredAny
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		Policy: PolicyConfig{
			MFARequiredAll:         false,
			MFARequiredAny:         false,
			MFARequiredCoveragePct: 0,
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	if idpPosture.Policy.MFARequired {
		t.Error("Policy.MFARequired = true, want false")
	}
	if idpPosture.Policy.MFARequiredCoveragePct == nil || *idpPosture.Policy.MFARequiredCoveragePct != 0 {
		t.Fatalf("Policy.MFARequiredCoveragePct = %v, want 0", idpPosture.Policy.MFARequiredCoveragePct)
	}
}

func TestToIDPPosture_NilPolicyValues(t *testing.T) {
	// Test that nil policy values result in zero values
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		Policy: PolicyConfig{
			SessionLifetimeMaxMinutes: nil,
			IdleTimeoutMaxMinutes:     nil,
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	if idpPosture.Policy.SessionLifetimeMaxMin != nil {
		t.Errorf("Policy.SessionLifetimeMaxMin = %v, want nil (nil input)", *idpPosture.Policy.SessionLifetimeMaxMin)
	}
	if idpPosture.Policy.IdleTimeoutMaxMin != nil {
		t.Errorf("Policy.IdleTimeoutMaxMin = %v, want nil (nil input)", *idpPosture.Policy.IdleTimeoutMaxMin)
	}
}

func TestIDPPostureJSONStructure(t *testing.T) {
	// Test that IDPPosture JSON output matches idp-posture@v1 schema
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		Posture: Posture{
			MFACoverage:          100,
			MFAPhishingResistant: 50,
			SSOCoverage:          90,
		},
		Users: UserMetrics{
			LockedOut: 1,
			Inactive:  5,
			Suspended: 4,
		},
		Apps: AppMetrics{
			ProvisioningEnabled: 75,
		},
		PrivilegedAccess: PrivilegedAccessMetrics{
			PrivilegedUsersCount:           2,
			SuperAdminCount:                1,
			StandingPrivilegedUsersCount:   2,
			PrivilegedMFACoveragePct:       100,
			PrivilegedPhishingResistantPct: 50,
		},
		Policy: PolicyConfig{
			MFARequiredAny:            true,
			MFARequiredCoveragePct:    50,
			SessionLifetimeMaxMinutes: intPtr(480),
			IdleTimeoutMaxMinutes:     intPtr(30),
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	// Marshal to JSON and unmarshal to map to verify structure
	jsonBytes, err := json.Marshal(idpPosture)
	if err != nil {
		t.Fatalf("failed to marshal IDPPosture: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	// Check top-level required fields per idp-posture@v1 schema
	topLevelRequired := []string{
		"schema_version", "collected_at", "provider", "org_domain",
		"user_security",
	}
	for _, field := range topLevelRequired {
		if _, ok := data[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Check user_security fields
	userSecurity, ok := data["user_security"].(map[string]interface{})
	if !ok {
		t.Fatal("user_security is not an object")
	}
	userSecurityFields := []string{
		"mfa_coverage_pct", "mfa_phishing_resistant_pct", "inactive_pct", "locked_out_pct",
	}
	for _, field := range userSecurityFields {
		if _, ok := userSecurity[field]; !ok {
			t.Errorf("user_security missing required field: %s", field)
		}
	}

	// Check app_security fields
	appSecurity, ok := data["app_security"].(map[string]interface{})
	if !ok {
		t.Fatal("app_security is not an object")
	}
	appSecurityFields := []string{"sso_coverage_pct", "provisioning_enabled_pct", "deprovisioning_enabled_pct"}
	for _, field := range appSecurityFields {
		if _, ok := appSecurity[field]; !ok {
			t.Errorf("app_security missing required field: %s", field)
		}
	}

	// Check policy fields
	policy, ok := data["policy"].(map[string]interface{})
	if !ok {
		t.Fatal("policy is not an object")
	}
	policyFields := []string{"mfa_required", "mfa_required_coverage_pct", "session_lifetime_max_min", "idle_timeout_max_min"}
	for _, field := range policyFields {
		if _, ok := policy[field]; !ok {
			t.Errorf("policy missing required field: %s", field)
		}
	}

	if _, ok := policy["mfa_required_coverage_pct"]; !ok {
		t.Error("policy missing mfa_required_coverage_pct")
	}

	lifecycle, ok := data["lifecycle"].(map[string]interface{})
	if !ok {
		t.Fatal("lifecycle is not an object")
	}
	if _, ok := lifecycle["suspended_pct"]; !ok {
		t.Error("lifecycle missing suspended_pct")
	}

	privilegedAccess, ok := data["privileged_access"].(map[string]interface{})
	if !ok {
		t.Fatal("privileged_access is not an object")
	}
	privilegedFields := []string{
		"privileged_users_count",
		"super_admin_count",
		"privileged_mfa_coverage_pct",
		"privileged_phishing_resistant_pct",
		"standing_privileged_users_count",
	}
	for _, field := range privilegedFields {
		if _, ok := privilegedAccess[field]; !ok {
			t.Errorf("privileged_access missing field: %s", field)
		}
	}
}

func TestCollect_WithDeviceAccessRequired(t *testing.T) {
	now := time.Now()
	recentLogin := now.AddDate(0, 0, -7)

	client := &mockOktaClient{
		users: []okta.User{
			{ID: "admin1", Status: "ACTIVE", LastLogin: recentLogin},
			{ID: "user1", Status: "ACTIVE", LastLogin: recentLogin},
			{ID: "user2", Status: "ACTIVE", LastLogin: recentLogin},
		},
		factors: make(map[string][]okta.Factor),
		apps:    []okta.Application{},
		groupUsers: map[string][]okta.User{
			"grp-admins": {{ID: "admin1"}},
		},
		roleAssignees: []okta.RoleAssignedUser{{ID: "admin1"}},
		userRoles: map[string][]okta.RoleAssignment{
			"admin1": {{ID: "r1", Type: "SUPER_ADMIN"}},
		},
		policies: map[string][]okta.Policy{
			"OKTA_SIGN_ON": {
				{
					ID:       "admins-policy",
					Status:   "ACTIVE",
					Priority: 1,
					Conditions: okta.PolicyConditions{
						People: &okta.PolicyPeopleCondition{
							Groups: &struct {
								Include []string `json:"include,omitempty"`
								Exclude []string `json:"exclude,omitempty"`
							}{
								Include: []string{"grp-admins"},
							},
						},
					},
				},
				{
					ID:       "default-policy",
					Status:   "ACTIVE",
					Priority: 2,
				},
			},
		},
		policyRules: map[string][]okta.PolicyRule{
			"admins-policy": {
				{
					ID:       "rule1",
					Status:   "ACTIVE",
					Priority: 1,
					Conditions: okta.PolicyRuleConditions{
						Device: &okta.DeviceCondition{
							Managed: "true",
						},
					},
					Actions: okta.PolicyRuleActions{
						Signon: &okta.SignonActions{RequireFactor: true},
					},
				},
			},
			"default-policy": {
				{
					ID:       "rule2",
					Status:   "ACTIVE",
					Priority: 1,
					Actions: okta.PolicyRuleActions{
						Signon: &okta.SignonActions{RequireFactor: false},
					},
				},
			},
		},
		deviceAssurancePolicies: []okta.DeviceAssurancePolicy{
			{ID: "dap1", Name: "iOS Policy", Platform: "IOS"},
			{ID: "dap2", Name: "macOS Policy", Platform: "MACOS"},
		},
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !posture.DeviceAccess.ManagedDeviceRequired {
		t.Error("expected ManagedDeviceRequired to be true")
	}

	// Only admin1 is covered by managed device requirement (1 out of 3 = 33%)
	if posture.DeviceAccess.ManagedDeviceRequiredCoveragePct != 33 {
		t.Errorf("expected ManagedDeviceRequiredCoveragePct=33, got %d", posture.DeviceAccess.ManagedDeviceRequiredCoveragePct)
	}

	// admin1 is covered by managed device requirement
	if !posture.DeviceAccess.ManagedDeviceRequiredForAdmins {
		t.Error("expected ManagedDeviceRequiredForAdmins to be true")
	}

	if posture.DeviceAccess.DeviceAssurancePoliciesCount != 2 {
		t.Errorf("expected DeviceAssurancePoliciesCount=2, got %d", posture.DeviceAccess.DeviceAssurancePoliciesCount)
	}
}

func TestCollect_WithoutDeviceAccessRequired(t *testing.T) {
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "user1", Status: "ACTIVE", LastLogin: time.Now()},
		},
		factors:  make(map[string][]okta.Factor),
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
	}

	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.DeviceAccess.ManagedDeviceRequired {
		t.Error("expected ManagedDeviceRequired to be false when no policies have device conditions")
	}

	if posture.DeviceAccess.ManagedDeviceRequiredCoveragePct != 0 {
		t.Errorf("expected ManagedDeviceRequiredCoveragePct=0, got %d", posture.DeviceAccess.ManagedDeviceRequiredCoveragePct)
	}

	if posture.DeviceAccess.ManagedDeviceRequiredForAdmins {
		t.Error("expected ManagedDeviceRequiredForAdmins to be false when no admins and no policies")
	}

	if posture.DeviceAccess.DeviceAssurancePoliciesCount != 0 {
		t.Errorf("expected DeviceAssurancePoliciesCount=0, got %d", posture.DeviceAccess.DeviceAssurancePoliciesCount)
	}
}

func TestToIDPPosture_WithDeviceAccess(t *testing.T) {
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		DeviceAccess: DeviceAccessMetrics{
			ManagedDeviceRequired:            true,
			ManagedDeviceRequiredCoveragePct: 75,
			ManagedDeviceRequiredForAdmins:   true,
			DeviceAssurancePoliciesCount:     3,
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	if idpPosture.DeviceAccess == nil {
		t.Fatal("DeviceAccess = nil, want non-nil when ManagedDeviceRequired is true")
	}
	if idpPosture.DeviceAccess.ManagedDeviceRequired == nil || !*idpPosture.DeviceAccess.ManagedDeviceRequired {
		t.Error("DeviceAccess.ManagedDeviceRequired = false, want true")
	}
	if idpPosture.DeviceAccess.ManagedDeviceRequiredForAdmins == nil || !*idpPosture.DeviceAccess.ManagedDeviceRequiredForAdmins {
		t.Error("DeviceAccess.ManagedDeviceRequiredForAdmins = false, want true")
	}
}

func TestToIDPPosture_WithoutDeviceAccess(t *testing.T) {
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		DeviceAccess: DeviceAccessMetrics{
			ManagedDeviceRequired:            false,
			ManagedDeviceRequiredCoveragePct: 0,
			ManagedDeviceRequiredForAdmins:   false,
			DeviceAssurancePoliciesCount:     0,
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	// DeviceAccess should be nil when ManagedDeviceRequired is false (no positive evidence)
	if idpPosture.DeviceAccess != nil {
		t.Error("DeviceAccess should be nil when ManagedDeviceRequired is false")
	}
}

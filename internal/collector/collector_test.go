package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// mockOktaClient implements okta.OktaClient for testing.
type mockOktaClient struct {
	identity                   *okta.Identity // who SignIn says the client is; an API token's owner when nil
	signInErr                  error
	users                      []okta.User
	usersErr                   error
	factors                    map[string][]okta.Factor // userID -> factors
	factorsErr                 error
	factorsErrFor              map[string]error       // userID -> the error reading their factors
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
	orgContacts                []okta.OrgContact
	orgContactsErr             error
}

func (m *mockOktaClient) SignIn(ctx context.Context) (*okta.Identity, error) {
	if m.signInErr != nil {
		return nil, m.signInErr
	}
	if m.identity != nil {
		return m.identity, nil
	}
	return &okta.Identity{Kind: "api_token", AuthMethod: componentsdk.AuthAPIToken, ID: "00u-token-owner"}, nil
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
	if err := m.factorsErrFor[userID]; err != nil {
		return nil, err
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

// FetchOrgSettings answers like the client, which never returns a nil org
// without an error.
func (m *mockOktaClient) FetchOrgSettings(ctx context.Context) (*okta.OrgSettings, error) {
	if m.orgErr != nil {
		return nil, m.orgErr
	}
	if m.orgSettings == nil {
		return nil, &okta.APIStatusError{StatusCode: 404, Path: "/api/v1/org"}
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

	// A percentage of no users or no apps has no value, and the zero
	// population says why.
	if posture.Posture.MFACoverage != nil || posture.Posture.SSOCoverage != nil {
		t.Errorf("expected null coverage for an empty org, got mfa=%s sso=%s", showInt(posture.Posture.MFACoverage), showInt(posture.Posture.SSOCoverage))
	}
	assertInt(t, "Users.TotalCount", posture.Users.TotalCount, 0)
	assertInt(t, "Apps.TotalCount", posture.Apps.TotalCount, 0)

	// Each numerator over a population of 0 is 0.
	for name, count := range map[string]*int{
		"Posture.MFAEnrolledUsersCount":                     posture.Posture.MFAEnrolledUsersCount,
		"Posture.MFAPhishingResistantUsersCount":            posture.Posture.MFAPhishingResistantUsersCount,
		"Users.PasswordExpiredCount":                        posture.Users.PasswordExpiredCount,
		"Users.LockedOutCount":                              posture.Users.LockedOutCount,
		"Users.InactiveCount":                               posture.Users.InactiveCount,
		"Users.SuspendedCount":                              posture.Users.SuspendedCount,
		"Apps.SSOCount":                                     posture.Apps.SSOCount,
		"Apps.ProvisioningEnabledCount":                     posture.Apps.ProvisioningEnabledCount,
		"Apps.DeprovisioningEnabledCount":                   posture.Apps.DeprovisioningEnabledCount,
		"PrivilegedAccess.PrivilegedMFAEnrolledCount":       posture.PrivilegedAccess.PrivilegedMFAEnrolledCount,
		"PrivilegedAccess.PrivilegedPhishingResistantCount": posture.PrivilegedAccess.PrivilegedPhishingResistantCount,
		"Policy.MFARequiredUsersCount":                      posture.Policy.MFARequiredUsersCount,
		"DeviceAccess.ManagedDeviceRequiredUsersCount":      posture.DeviceAccess.ManagedDeviceRequiredUsersCount,
		"DeviceAccess.ManagedDeviceRequiredAdminsCount":     posture.DeviceAccess.ManagedDeviceRequiredAdminsCount,
	} {
		assertInt(t, name, count, 0)
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
	assertInt(t, "Posture.MFACoverage", posture.Posture.MFACoverage, 60)

	// Only user4 has phishing-resistant MFA (webauthn) = 20%
	assertInt(t, "Posture.MFAPhishingResistant", posture.Posture.MFAPhishingResistant, 20)

	// 1 user locked out = 20%
	assertInt(t, "Users.LockedOut", posture.Users.LockedOut, 20)

	// 1 user inactive (user3) = 20%
	assertInt(t, "Users.Inactive", posture.Users.Inactive, 20)

	// 1 user suspended (user6) = 20%
	assertInt(t, "Users.Suspended", posture.Users.Suspended, 20)

	// Each percentage's numerator.
	assertInt(t, "Posture.MFAEnrolledUsersCount", posture.Posture.MFAEnrolledUsersCount, 3)
	assertInt(t, "Posture.MFAPhishingResistantUsersCount", posture.Posture.MFAPhishingResistantUsersCount, 1)
	assertInt(t, "Users.PasswordExpiredCount", posture.Users.PasswordExpiredCount, 0)
	assertInt(t, "Users.LockedOutCount", posture.Users.LockedOutCount, 1)
	assertInt(t, "Users.InactiveCount", posture.Users.InactiveCount, 1)
	assertInt(t, "Users.SuspendedCount", posture.Users.SuspendedCount, 1)
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

	assertInt(t, "PrivilegedAccess.PrivilegedUsersCount", posture.PrivilegedAccess.PrivilegedUsersCount, 2)
	assertInt(t, "PrivilegedAccess.SuperAdminCount", posture.PrivilegedAccess.SuperAdminCount, 1)
	assertInt(t, "PrivilegedAccess.StandingPrivilegedUsersCount", posture.PrivilegedAccess.StandingPrivilegedUsersCount, 2)
	assertInt(t, "PrivilegedAccess.PrivilegedMFACoveragePct", posture.PrivilegedAccess.PrivilegedMFACoveragePct, 100)
	assertInt(t, "PrivilegedAccess.PrivilegedPhishingResistantPct", posture.PrivilegedAccess.PrivilegedPhishingResistantPct, 50)
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
	assertInt(t, "Posture.SSOCoverage", posture.Posture.SSOCoverage, 75)

	// 1 app with provisioning = 25%
	assertInt(t, "Apps.ProvisioningEnabled", posture.Apps.ProvisioningEnabled, 25)

	// 1 app with deprovisioning = 25%
	assertInt(t, "Apps.DeprovisioningEnabled", posture.Apps.DeprovisioningEnabled, 25)
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

	assertInt(t, "Policy.PolicyCount", posture.Policy.PolicyCount, 1)

	assertBool(t, "Policy.MFARequiredAll", posture.Policy.MFARequiredAll, true)

	assertBool(t, "Policy.MFARequiredAny", posture.Policy.MFARequiredAny, true)

	assertInt(t, "Policy.MFARequiredCoveragePct", posture.Policy.MFARequiredCoveragePct, 100)

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

	assertInt(t, "Policy.PolicyCount", posture.Policy.PolicyCount, 2)

	// Only one policy requires MFA
	assertBool(t, "Policy.MFARequiredAll", posture.Policy.MFARequiredAll, false)

	assertBool(t, "Policy.MFARequiredAny", posture.Policy.MFARequiredAny, true)

	assertInt(t, "Policy.MFARequiredCoveragePct", posture.Policy.MFARequiredCoveragePct, 33)

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
	if cr.Label != "Billing Admin" {
		t.Errorf("custom role wrong: %+v", cr)
	}
	assertInt(t, "CustomRoles[0].PermissionCount", cr.PermissionCount, 2)

	if len(posture.Policy.Policies) != 1 {
		t.Fatalf("expected 1 policy summary, got %d", len(posture.Policy.Policies))
	}
	ps := posture.Policy.Policies[0]
	if ps.Name != "Default Sign-on" || ps.RuleCount != 1 || ps.ScopeSummary != "everyone" {
		t.Errorf("policy summary wrong: %+v", ps)
	}
}

func TestPrivileged_LeavesOutWorkflowsAdmin(t *testing.T) {
	roles := []okta.IAMRole{
		{ID: "WORKFLOWS_ADMIN", Label: "Workflows Administrator", Description: "An admin role for managing workflows"},
		{ID: "cr1", Label: "Billing Admin"},
	}

	client := &mockOktaClient{iamRoles: roles, rolePermissions: map[string][]string{"cr1": {"okta.users.read"}}}
	posture, err := NewWithClient(Config{OrgDomain: "test.okta.com"}, client).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := posture.PrivilegedAccess.CustomRoles; len(got) != 1 || got[0].Name != "cr1" {
		t.Fatalf("custom roles = %+v, want only cr1", got)
	}

	client = &mockOktaClient{iamRoles: roles, rolePermissionsErr: &okta.APIStatusError{StatusCode: 500, Path: "/api/v1/iam/roles/cr1/permissions"}}
	rec := &componentsdk.Recorder{}
	if _, err := NewWithClient(Config{OrgDomain: "test.okta.com", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelAudit); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := gapAt(rec, "/privileged_access/custom_roles/0/permission_count"); !ok {
		t.Errorf("expected the permission_count gap on row 0, got %+v", rec.Gaps())
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

	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{OrgDomain: "test.okta.com", Recorder: rec}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}

	// Built-in roles still surface in the inventory.
	if len(posture.PrivilegedAccess.Inventory) != 1 {
		t.Errorf("expected built-in role inventory to survive, got %d rows", len(posture.PrivilegedAccess.Inventory))
	}
	// Custom roles are left out with a not_licensed gap, never an empty list.
	if posture.PrivilegedAccess.CustomRoles != nil {
		t.Errorf("expected custom_roles left out, got %v", posture.PrivilegedAccess.CustomRoles)
	}
	if g, ok := gapAt(rec, "/privileged_access/custom_roles"); !ok || g.Code != componentsdk.CodeNotLicensed {
		t.Errorf("expected a not_licensed gap at custom_roles, got %+v", rec.Gaps())
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
	// leaving the privileged metrics out with a gap plus a diagnostic.
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "user1", Status: "ACTIVE", LastLogin: time.Now(), Profile: okta.UserProfile{Login: "user1@acme.com"}},
		},
		factors:          map[string][]okta.Factor{"user1": {{ID: "f1", FactorType: "webauthn", Status: "ACTIVE"}}},
		apps:             []okta.Application{{ID: "app1", SignOnMode: "SAML_2_0", Status: "ACTIVE"}},
		policies:         make(map[string][]okta.Policy),
		roleAssigneesErr: &okta.APIStatusError{StatusCode: 403, Path: "/api/v1/iam/assignees/users"},
	}

	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{OrgDomain: "test.okta.com", Recorder: rec}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}

	// Other surfaces still collected.
	assertInt(t, "Posture.MFACoverage", posture.Posture.MFACoverage, 100)
	// Privileged metrics are left out, never zero.
	if posture.PrivilegedAccess.PrivilegedUsersCount != nil {
		t.Errorf("expected privileged_users_count left out on 403, got %d", *posture.PrivilegedAccess.PrivilegedUsersCount)
	}
	if g, ok := gapAt(rec, "/privileged_access/privileged_users_count"); !ok || g.Code != componentsdk.CodePermissionDenied {
		t.Errorf("expected a permission_denied gap at privileged_users_count, got %+v", rec.Gaps())
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

func TestRefusedReads_NameTheScopeOnlyWhenOktaDidNotGrantIt(t *testing.T) {
	asked := scopesForLevel(componentsdk.LevelAudit)
	serviceApp := func(granted []string) okta.Identity {
		return okta.Identity{Kind: "service_app", AuthMethod: componentsdk.AuthPrivateKeyJWT, ID: "0oa-app", RequestedScopes: asked, Scopes: granted}
	}
	type want struct{ missing, warning string }
	cases := []struct {
		name     string
		identity okta.Identity
		logs     want
		tokens   want
	}{
		{
			name: "service app without the scopes", identity: serviceApp(baseOAuthScopes),
			logs:   want{"okta.logs.read", "system log: access denied (403; grant okta.logs.read and an admin role that can read it)"},
			tokens: want{"okta.apiTokens.read", "api tokens: access denied (403; grant okta.apiTokens.read and the SUPER_ADMIN role)"},
		},
		{
			name: "service app with the scopes", identity: serviceApp(asked),
			logs:   want{"", "system log: access denied (403; okta.logs.read is granted, so the service app needs an admin role that can read it)"},
			tokens: want{"", "api tokens: access denied (403; okta.apiTokens.read is granted, so the service app needs the SUPER_ADMIN role)"},
		},
		{
			name: "api token", identity: okta.Identity{Kind: "api_token", AuthMethod: componentsdk.AuthAPIToken, ID: "00u1"},
			logs:   want{"", "system log: access denied (403; the API token's owner needs an admin role that can read it)"},
			tokens: want{"", "api tokens: access denied (403; the API token's owner needs the SUPER_ADMIN role)"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := richClient()
			client.identity = &tc.identity
			client.systemLogErr = &okta.APIStatusError{StatusCode: 403, Path: "/api/v1/logs", Code: "E0000006"}
			client.apiTokensErr = &okta.APIStatusError{StatusCode: 403, Path: "/api/v1/api-tokens", Code: "E0000006"}
			rec := &componentsdk.Recorder{}
			c := NewWithClient(Config{OrgDomain: "acme.okta.com", Recorder: rec}, client)
			if _, err := c.Collect(context.Background(), componentsdk.LevelAudit); err != nil {
				t.Fatal(err)
			}
			for pointer, w := range map[string]want{"/system_log": tc.logs, "/api_tokens": tc.tokens} {
				g, ok := gapAt(rec, pointer)
				if !ok || g.Code != componentsdk.CodePermissionDenied || g.MissingPermission != w.missing || g.Warning != w.warning {
					t.Errorf("gap at %s = %+v, want permission_denied naming %q with warning %q", pointer, g, w.missing, w.warning)
				}
			}
		})
	}
}

func TestFailedReads_CarryTheirWarning(t *testing.T) {
	client := richClient()
	client.systemLogErr = &okta.APIStatusError{StatusCode: 500, Path: "/api/v1/logs"}
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{OrgDomain: "acme.okta.com", Recorder: rec}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}
	const warning = "system log: okta API /api/v1/logs returned status 500"
	g, ok := gapAt(rec, "/system_log")
	if !ok || g.Code != componentsdk.CodeVendorError || g.MissingPermission != "" || g.Warning != warning {
		t.Errorf("gap = %+v, want vendor_error with the warning %q and no permission", g, warning)
	}
	if posture.Diagnostics == nil || !strings.Contains(strings.Join(posture.Diagnostics.Warnings, "\n"), warning) {
		t.Errorf("diagnostics = %+v, want the same warning", posture.Diagnostics)
	}
}

func TestCoreSurfaces_DegradeOnForbidden(t *testing.T) {
	// Every core surface returns 403 (a maximally locked-down service app). The
	// run must still succeed, leaving the core metrics out with a gap each and
	// a diagnostic per skipped surface rather than failing outright.
	forbidden := func(path string) error { return &okta.APIStatusError{StatusCode: 403, Path: path} }
	client := &mockOktaClient{
		usersErr:                   forbidden("/api/v1/users"),
		appsErr:                    forbidden("/api/v1/apps"),
		policiesErr:                forbidden("/api/v1/policies"),
		deviceAssurancePoliciesErr: forbidden("/api/v1/device-assurances"),
		roleAssigneesErr:           forbidden("/api/v1/iam/assignees/users"),
	}

	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{OrgDomain: "test.okta.com", Recorder: rec}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("expected degraded success, got error: %v", err)
	}

	core := map[string]*int{
		"/posture/mfa_coverage":                          posture.Posture.MFACoverage,
		"/apps/provisioning_enabled":                     posture.Apps.ProvisioningEnabled,
		"/privileged_access/privileged_users_count":      posture.PrivilegedAccess.PrivilegedUsersCount,
		"/policy/policy_count":                           posture.Policy.PolicyCount,
		"/device_access/device_assurance_policies_count": posture.DeviceAccess.DeviceAssurancePoliciesCount,
	}
	for pointer, value := range core {
		if value != nil {
			t.Errorf("%s = %d, want it left out", pointer, *value)
		}
		if g, ok := gapAt(rec, pointer); !ok || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("expected a permission_denied gap at %s, got %+v", pointer, g)
		}
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
	assertBool(t, "user has_active_mfa", u.HasActiveMFA, true)
	assertBool(t, "user has_phishing_resistant_mfa", u.HasPhishingResistantMFA, true)
	assertBool(t, "admin has_active_mfa", pu.HasActiveMFA, true)
	assertBool(t, "admin has_phishing_resistant_mfa", pu.HasPhishingResistantMFA, true)

	if len(posture.Policy.Policies) != 1 || len(posture.Policy.Policies[0].Rules) != 1 {
		t.Fatalf("expected 1 policy with 1 rule detail, got %+v", posture.Policy.Policies)
	}
	rule := posture.Policy.Policies[0].Rules[0]
	if rule.Name != "Require MFA" || rule.Access != "ALLOW" || rule.RequireFactor == nil || !*rule.RequireFactor {
		t.Errorf("rule detail wrong: %+v", rule)
	}
}

func TestMFAFlags_LeftOutWhenFactorsCannotBeRead(t *testing.T) {
	now := time.Now()
	client := &mockOktaClient{
		users: []okta.User{
			{ID: "admin1", Status: "ACTIVE", LastLogin: now, Profile: okta.UserProfile{Login: "admin1@acme.com"}},
			{ID: "user2", Status: "ACTIVE", LastLogin: now, Profile: okta.UserProfile{Login: "user2@acme.com"}},
		},
		factors:       map[string][]okta.Factor{"user2": {{ID: "f2", FactorType: "push", Status: "ACTIVE"}}},
		apps:          []okta.Application{},
		roleAssignees: []okta.RoleAssignedUser{{ID: "admin1"}},
		userRoles:     map[string][]okta.RoleAssignment{"admin1": {{ID: "r1", Type: "SUPER_ADMIN"}}},
		policies:      make(map[string][]okta.Policy),
	}
	client.factorsErrFor = map[string]error{"admin1": &okta.APIStatusError{StatusCode: 500, Path: "/api/v1/users/admin1/factors"}}

	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{OrgDomain: "test.okta.com", Recorder: rec}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatal(err)
	}

	// The admin's row leaves both flags out with a gap, in both lists; the
	// other user's row says what their factors show.
	admin, other := posture.Users.Inventory[0], posture.Users.Inventory[1]
	if admin.HasActiveMFA != nil || admin.HasPhishingResistantMFA != nil {
		t.Errorf("admin1's flags = %s, %s; want them left out", showBool(admin.HasActiveMFA), showBool(admin.HasPhishingResistantMFA))
	}
	assertBool(t, "user2 has_active_mfa", other.HasActiveMFA, true)
	assertBool(t, "user2 has_phishing_resistant_mfa", other.HasPhishingResistantMFA, false)
	if pu := posture.PrivilegedAccess.Inventory[0]; pu.HasActiveMFA != nil || pu.HasPhishingResistantMFA != nil {
		t.Errorf("admin row flags = %s, %s; want them left out", showBool(pu.HasActiveMFA), showBool(pu.HasPhishingResistantMFA))
	}
	for _, pointer := range []string{
		"/users/inventory/0/has_active_mfa", "/users/inventory/0/has_phishing_resistant_mfa",
		"/privileged_access/inventory/0/has_active_mfa", "/privileged_access/inventory/0/has_phishing_resistant_mfa",
	} {
		if g, ok := gapAt(rec, pointer); !ok || g.Code != componentsdk.CodeVendorError {
			t.Errorf("expected a vendor_error gap at %s, got %+v", pointer, g)
		}
	}

	// The counts the flags roll up to are left out with their percentages.
	for pointer, count := range map[string]*int{
		"/posture/mfa_enrolled_users_count":                      posture.Posture.MFAEnrolledUsersCount,
		"/posture/mfa_phishing_resistant_users_count":            posture.Posture.MFAPhishingResistantUsersCount,
		"/privileged_access/privileged_mfa_enrolled_count":       posture.PrivilegedAccess.PrivilegedMFAEnrolledCount,
		"/privileged_access/privileged_phishing_resistant_count": posture.PrivilegedAccess.PrivilegedPhishingResistantCount,
	} {
		if count != nil {
			t.Errorf("%s = %d, want it left out", pointer, *count)
		}
		if g, ok := gapAt(rec, pointer); !ok || g.Status != componentsdk.GapPartial || g.Unmeasured != 1 {
			t.Errorf("expected a partial gap with 1 unmeasured at %s, got %+v", pointer, g)
		}
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
	assertInt(t, "Posture.MFAPhishingResistant", posture.Posture.MFAPhishingResistant, 50)
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
		{0, 100, 0},
		{50, 100, 50},
		{1, 3, 33},
		{2, 3, 66},
		{100, 100, 100},
	}

	for _, tt := range tests {
		assertInt(t, fmt.Sprintf("percent(%d, %d)", tt.count, tt.total), percent(tt.count, tt.total), tt.expected)
	}

	// A percentage of nothing has no value.
	if got := percent(0, 0); got != nil {
		t.Errorf("percent(0, 0) = %d, want nil", *got)
	}
}

func TestSchemaVersion(t *testing.T) {
	if SchemaVersion != "1.0.0" {
		t.Errorf("expected schema version 1.0.0, got %s", SchemaVersion)
	}
}

func TestNewOrgPosture(t *testing.T) {
	posture := NewOrgPosture("test.okta.com", time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))

	if posture.SchemaVersion != SchemaVersion {
		t.Errorf("expected schema version %s, got %s", SchemaVersion, posture.SchemaVersion)
	}

	if posture.OrgDomain != "test.okta.com" {
		t.Errorf("expected org domain test.okta.com, got %s", posture.OrgDomain)
	}

	if posture.CollectedAt == "" {
		t.Error("expected collected_at to be set")
	}

	// collected_at is the run clock's time in RFC 3339.
	if posture.CollectedAt != "2026-01-01T12:00:00Z" {
		t.Errorf("collected_at = %s, want 2026-01-01T12:00:00Z", posture.CollectedAt)
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

// assertInt fails unless got points to want.
func assertInt(t *testing.T, name string, got *int, want int) {
	t.Helper()
	if got == nil || *got != want {
		t.Errorf("%s = %s, want %d", name, showInt(got), want)
	}
}

// assertFloat fails unless got points to want.
func assertFloat(t *testing.T, name string, got *float64, want float64) {
	t.Helper()
	if got == nil || *got != want {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

// assertBool fails unless got points to want.
func assertBool(t *testing.T, name string, got *bool, want bool) {
	t.Helper()
	if got == nil || *got != want {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

func showInt(p *int) string {
	if p == nil {
		return "null"
	}
	return strconv.Itoa(*p)
}

func showBool(b *bool) string {
	if b == nil {
		return "null"
	}
	return strconv.FormatBool(*b)
}

// gapAt returns the gap recorded at pointer in the detailed artifact.
func gapAt(rec *componentsdk.Recorder, pointer string) (componentsdk.Gap, bool) {
	for _, g := range rec.Gaps() {
		if g.Path == detailedPath && g.Pointer == pointer {
			return g, true
		}
	}
	return componentsdk.Gap{}, false
}

func TestToIDPPosture(t *testing.T) {
	// Test transformation from OrgPosture to normalized IDPPosture
	orgPosture := &OrgPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   "2024-01-15T10:00:00Z",
		OrgDomain:     "acme.okta.com",
		Posture: Posture{
			MFACoverage:          intPtr(95),
			MFAPhishingResistant: intPtr(40),
			SSOCoverage:          intPtr(85),
		},
		Users: UserMetrics{
			TotalCount:      intPtr(100),
			PasswordExpired: intPtr(5),
			LockedOut:       intPtr(2),
			Inactive:        intPtr(8),
			Suspended:       intPtr(7),
		},
		Apps: AppMetrics{
			TotalCount:            intPtr(20),
			ProvisioningEnabled:   intPtr(60),
			DeprovisioningEnabled: intPtr(45),
		},
		PrivilegedAccess: PrivilegedAccessMetrics{
			PrivilegedUsersCount:           intPtr(3),
			SuperAdminCount:                intPtr(1),
			StandingPrivilegedUsersCount:   intPtr(3),
			PrivilegedMFACoveragePct:       intPtr(67),
			PrivilegedPhishingResistantPct: intPtr(33),
		},
		Policy: PolicyConfig{
			PolicyCount:               intPtr(3),
			MFARequiredAll:            boolPtr(false),
			MFARequiredAny:            boolPtr(true),
			MFARequiredCoveragePct:    intPtr(66),
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
	if idpPosture.CollectedAt != orgPosture.CollectedAt {
		t.Errorf("CollectedAt = %q, want the detailed artifact's %q", idpPosture.CollectedAt, orgPosture.CollectedAt)
	}

	// Verify user_security mappings
	if idpPosture.UserSecurity == nil {
		t.Fatal("UserSecurity = nil, want non-nil")
	}
	assertFloat(t, "UserSecurity.MFACoveragePct", idpPosture.UserSecurity.MFACoveragePct, 95)
	assertFloat(t, "UserSecurity.MFAPhishingResistantPct", idpPosture.UserSecurity.MFAPhishingResistantPct, 40)
	assertFloat(t, "UserSecurity.InactivePct", idpPosture.UserSecurity.InactivePct, 8)
	assertFloat(t, "UserSecurity.LockedOutPct", idpPosture.UserSecurity.LockedOutPct, 2)
	if idpPosture.Lifecycle == nil {
		t.Fatal("Lifecycle = nil, want non-nil")
	}
	assertFloat(t, "Lifecycle.SuspendedPct", idpPosture.Lifecycle.SuspendedPct, 7)
	if idpPosture.PrivilegedAccess == nil {
		t.Fatal("PrivilegedAccess = nil, want non-nil")
	}
	assertInt(t, "PrivilegedUsersCount", idpPosture.PrivilegedAccess.PrivilegedUsersCount, 3)
	assertInt(t, "SuperAdminCount", idpPosture.PrivilegedAccess.SuperAdminCount, 1)
	assertInt(t, "StandingPrivilegedUsersCount", idpPosture.PrivilegedAccess.StandingPrivilegedUsersCount, 3)
	assertFloat(t, "PrivilegedMFACoveragePct", idpPosture.PrivilegedAccess.PrivilegedMFACoveragePct, 67)
	assertFloat(t, "PrivilegedPhishingResistantPct", idpPosture.PrivilegedAccess.PrivilegedPhishingResistantPct, 33)

	// Verify app_security mappings
	if idpPosture.AppSecurity == nil {
		t.Fatal("AppSecurity = nil, want non-nil")
	}
	assertFloat(t, "AppSecurity.SSOCoveragePct", idpPosture.AppSecurity.SSOCoveragePct, 85)
	assertFloat(t, "AppSecurity.ProvisioningEnabledPct", idpPosture.AppSecurity.ProvisioningEnabledPct, 60)
	assertFloat(t, "AppSecurity.DeprovisioningEnabledPct", idpPosture.AppSecurity.DeprovisioningEnabledPct, 45)

	// Verify policy mappings
	if idpPosture.Policy == nil {
		t.Fatal("Policy = nil, want non-nil")
	}
	assertBool(t, "Policy.MFARequired", idpPosture.Policy.MFARequired, false)
	assertFloat(t, "Policy.MFARequiredCoveragePct", idpPosture.Policy.MFARequiredCoveragePct, 66)
	assertInt(t, "Policy.SessionLifetimeMaxMin", idpPosture.Policy.SessionLifetimeMaxMin, 1440)
	assertInt(t, "Policy.IdleTimeoutMaxMin", idpPosture.Policy.IdleTimeoutMaxMin, 120)
}

func TestToIDPPosture_MFARequiredAll(t *testing.T) {
	// Test that MFARequired is true when MFARequiredAll is true
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		Policy: PolicyConfig{
			MFARequiredAll:         boolPtr(true),
			MFARequiredAny:         boolPtr(true),
			MFARequiredCoveragePct: intPtr(100),
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	assertBool(t, "Policy.MFARequired", idpPosture.Policy.MFARequired, true)
	assertFloat(t, "Policy.MFARequiredCoveragePct", idpPosture.Policy.MFARequiredCoveragePct, 100)
}

func TestToIDPPosture_NoMFARequired(t *testing.T) {
	// Test that MFARequired is false when neither MFARequiredAll nor MFARequiredAny
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		Policy: PolicyConfig{
			MFARequiredAll:         boolPtr(false),
			MFARequiredAny:         boolPtr(false),
			MFARequiredCoveragePct: intPtr(0),
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	assertBool(t, "Policy.MFARequired", idpPosture.Policy.MFARequired, false)
	assertFloat(t, "Policy.MFARequiredCoveragePct", idpPosture.Policy.MFARequiredCoveragePct, 0)
}

func TestToIDPPosture_NilPolicyValues(t *testing.T) {
	// Values the detailed artifact left out are left out here too.
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		Apps:      AppMetrics{TotalCount: intPtr(1), ProvisioningEnabled: intPtr(100)},
		Policy: PolicyConfig{
			SessionLifetimeMaxMinutes: nil,
			IdleTimeoutMaxMinutes:     nil,
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	if idpPosture.Policy != nil {
		t.Errorf("Policy = %+v, want nil when the detailed policy values are all null", idpPosture.Policy)
	}
	if idpPosture.UserSecurity != nil {
		t.Errorf("UserSecurity = %+v, want nil when the user values are all null", idpPosture.UserSecurity)
	}
}

func TestToIDPPosture_NoEvidence(t *testing.T) {
	// A detailed artifact with every value left out has no normalized posture.
	orgPosture := &OrgPosture{OrgDomain: "test.okta.com"}
	if idpPosture := orgPosture.ToIDPPosture(); idpPosture != nil {
		t.Errorf("ToIDPPosture() = %+v, want nil", idpPosture)
	}
}

func TestIDPPostureJSONStructure(t *testing.T) {
	// Test that IDPPosture JSON output matches idp-posture@v1 schema
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		Posture: Posture{
			MFACoverage:          intPtr(100),
			MFAPhishingResistant: intPtr(50),
			SSOCoverage:          intPtr(90),
		},
		Users: UserMetrics{
			LockedOut: intPtr(1),
			Inactive:  intPtr(5),
			Suspended: intPtr(4),
		},
		Apps: AppMetrics{
			ProvisioningEnabled:   intPtr(75),
			DeprovisioningEnabled: intPtr(0),
		},
		PrivilegedAccess: PrivilegedAccessMetrics{
			PrivilegedUsersCount:           intPtr(2),
			SuperAdminCount:                intPtr(1),
			StandingPrivilegedUsersCount:   intPtr(2),
			PrivilegedMFACoveragePct:       intPtr(100),
			PrivilegedPhishingResistantPct: intPtr(50),
		},
		Policy: PolicyConfig{
			MFARequiredAll:            boolPtr(false),
			MFARequiredAny:            boolPtr(true),
			MFARequiredCoveragePct:    intPtr(50),
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

	assertBool(t, "DeviceAccess.ManagedDeviceRequired", posture.DeviceAccess.ManagedDeviceRequired, true)

	// Only admin1 is covered by managed device requirement (1 out of 3 = 33%)
	assertInt(t, "DeviceAccess.ManagedDeviceRequiredCoveragePct", posture.DeviceAccess.ManagedDeviceRequiredCoveragePct, 33)

	// admin1 is covered by managed device requirement
	assertBool(t, "DeviceAccess.ManagedDeviceRequiredForAdmins", posture.DeviceAccess.ManagedDeviceRequiredForAdmins, true)

	assertInt(t, "DeviceAccess.DeviceAssurancePoliciesCount", posture.DeviceAccess.DeviceAssurancePoliciesCount, 2)
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

	assertBool(t, "DeviceAccess.ManagedDeviceRequired", posture.DeviceAccess.ManagedDeviceRequired, false)

	assertInt(t, "DeviceAccess.ManagedDeviceRequiredCoveragePct", posture.DeviceAccess.ManagedDeviceRequiredCoveragePct, 0)

	// With no privileged users, "every admin is covered" has no answer.
	if posture.DeviceAccess.ManagedDeviceRequiredForAdmins != nil {
		t.Errorf("expected null ManagedDeviceRequiredForAdmins with no admins, got %v", *posture.DeviceAccess.ManagedDeviceRequiredForAdmins)
	}

	assertInt(t, "DeviceAccess.DeviceAssurancePoliciesCount", posture.DeviceAccess.DeviceAssurancePoliciesCount, 0)
}

func TestToIDPPosture_WithDeviceAccess(t *testing.T) {
	orgPosture := &OrgPosture{
		OrgDomain: "test.okta.com",
		DeviceAccess: DeviceAccessMetrics{
			ManagedDeviceRequired:            boolPtr(true),
			ManagedDeviceRequiredCoveragePct: intPtr(75),
			ManagedDeviceRequiredForAdmins:   boolPtr(true),
			DeviceAssurancePoliciesCount:     intPtr(3),
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
		Users:     UserMetrics{TotalCount: intPtr(1), Suspended: intPtr(0)},
		DeviceAccess: DeviceAccessMetrics{
			ManagedDeviceRequired:            boolPtr(false),
			ManagedDeviceRequiredCoveragePct: intPtr(0),
			ManagedDeviceRequiredForAdmins:   boolPtr(false),
			DeviceAssurancePoliciesCount:     intPtr(0),
		},
	}

	idpPosture := orgPosture.ToIDPPosture()

	// DeviceAccess should be nil when ManagedDeviceRequired is false (no positive evidence)
	if idpPosture.DeviceAccess != nil {
		t.Error("DeviceAccess should be nil when ManagedDeviceRequired is false")
	}
}

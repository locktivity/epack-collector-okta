package collector

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

const (
	kitOrgDomain = "acme.okta.com"
	kitBase      = "https://" + kitOrgDomain
	kitClientID  = "0oa-kit-service-app"
	kitKeyID     = "kit-key-1"
	kitAPIToken  = "kit-okta-api-token-0123456789"
)

// kitNow is the clock every kit run sees.
var kitNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

var (
	kitKeyOnce sync.Once
	kitKeyPEM  string
)

// kitPrivateKey returns a PEM RSA key generated once per test binary, so no
// key material lives in the repository.
func kitPrivateKey() string {
	kitKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			panic(err)
		}
		kitKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})
	return kitKeyPEM
}

// kitTenant is richClient's tenant at the kit's clock, grown so each
// per-item operation has a first, a middle, and a last call: six listed
// users (one more deprovisioned), three admins, three apps, sign-on and
// MFA-enrollment policies with group scopes, and three groups.
func kitTenant() *mockOktaClient {
	t := richClientAt(kitNow)
	day := 24 * time.Hour
	user := func(id, login, status string, lastLogin time.Time, userType string) okta.User {
		return okta.User{
			ID: id, Status: status, Created: kitNow.Add(-400 * day), LastLogin: lastLogin, LastUpdated: kitNow.Add(-2 * day),
			Profile: okta.UserProfile{Login: login, UserType: userType},
		}
	}
	t.users[0].LastLogin = kitNow.Add(-1 * day)
	t.users = append(t.users,
		user("u2", "bob@acme.com", "ACTIVE", kitNow.Add(-10*day), "Employee"),
		user("u3", "carol@acme.com", "LOCKED_OUT", kitNow.Add(-200*day), "Employee"),
		user("u4", "svc-ci@acme.com", "ACTIVE", time.Time{}, "Service Account"),
		user("u5", "dave@acme.com", "SUSPENDED", kitNow.Add(-30*day), "Employee"),
		user("u6", "erin@acme.com", "PASSWORD_EXPIRED", kitNow.Add(-5*day), "Employee"),
		user("u7", "frank@acme.com", "DEPROVISIONED", kitNow.Add(-90*day), "Employee"),
	)
	factor := func(id, factorType, status string) okta.Factor {
		return okta.Factor{ID: id, FactorType: factorType, Status: status, Created: kitNow.Add(-100 * day)}
	}
	t.factors["u2"] = []okta.Factor{factor("f2", "push", "ACTIVE"), factor("f3", "sms", "PENDING_ACTIVATION")}
	t.factors["u4"] = []okta.Factor{factor("f4", "token:software:totp", "ACTIVE")}
	t.factors["u5"] = []okta.Factor{factor("f5", "signed_nonce", "ACTIVE")}
	t.userGroupIDs = map[string][]string{"u1": {"g1", "g3"}, "u2": {"g1", "g3"}, "u3": {"g3"}, "u4": {"g2", "g3"}, "u5": {"g3"}, "u6": {"g2", "g3"}}

	t.roleAssignees = []okta.RoleAssignedUser{{ID: "u1"}, {ID: "u2"}, {ID: "u4"}, {ID: "u5"}}
	t.userRoles["u2"] = []okta.RoleAssignment{{ID: "r2", Type: "CUSTOM", Label: "Billing Admin", AssignmentType: "GROUP"}}
	t.userRoles["u4"] = []okta.RoleAssignment{{ID: "r3", Type: "READ_ONLY_ADMIN", AssignmentType: "USER"}}
	t.userRoles["u5"] = []okta.RoleAssignment{{ID: "r4", Type: "ORG_ADMIN", AssignmentType: "USER"}}
	t.iamRoles = []okta.IAMRole{{ID: "cr1", Label: "Billing Admin", Description: "Manages billing"}, {ID: "cr2", Label: "Help Desk"}}
	t.rolePermissions = map[string][]string{"cr1": {"okta.users.read", "okta.apps.read"}, "cr2": {"okta.users.read", "okta.users.manage", "okta.groups.read"}}

	t.apps = append(t.apps,
		okta.Application{ID: "app2", Label: "Chat", Name: "chat", SignOnMode: "OPENID_CONNECT", Status: "ACTIVE", Features: []string{"IMPORT_NEW_USERS", "PUSH_USER_DEACTIVATION"}},
		okta.Application{ID: "app3", Label: "Legacy Wiki", Name: "legacy_wiki", SignOnMode: "BROWSER_PLUGIN", Status: "INACTIVE"},
	)
	t.apps[0].Features = []string{"PUSH_NEW_USERS"}

	groupScope := func(include ...string) *okta.PolicyPeopleCondition {
		return &okta.PolicyPeopleCondition{Groups: &struct {
			Include []string `json:"include,omitempty"`
			Exclude []string `json:"exclude,omitempty"`
		}{Include: include}}
	}
	signon := func(requireFactor bool, lifetime, idle int) *okta.SignonActions {
		a := &okta.SignonActions{Access: "ALLOW", RequireFactor: requireFactor}
		a.Session.MaxSessionLifetimeMinutes = lifetime
		a.Session.MaxSessionIdleMinutes = idle
		return a
	}
	t.policies = map[string][]okta.Policy{
		PolicyTypeSignOn: {
			{ID: "p1", Name: "Admins", Type: PolicyTypeSignOn, Status: "ACTIVE", Priority: 1, Conditions: okta.PolicyConditions{People: groupScope("g1")}},
			{ID: "p2", Name: "Default", Type: PolicyTypeSignOn, Status: "ACTIVE", Priority: 2},
		},
		PolicyTypeMFAEnroll: {
			{ID: "p3", Name: "Engineering enrollment", Type: PolicyTypeMFAEnroll, Status: "ACTIVE", Priority: 1, Conditions: okta.PolicyConditions{People: groupScope("g2")}},
		},
	}
	t.policyRules = map[string][]okta.PolicyRule{
		"p1": {{ID: "r1", Name: "Admins on managed devices", Status: "ACTIVE", Priority: 1,
			Conditions: okta.PolicyRuleConditions{Device: &okta.DeviceCondition{Managed: "true"}},
			Actions:    okta.PolicyRuleActions{Signon: signon(true, 60, 15)}}},
		"p2": {{ID: "r2", Name: "Default", Status: "ACTIVE", Priority: 1, Actions: okta.PolicyRuleActions{Signon: signon(false, 720, 60)}}},
		"p3": {{ID: "r3", Name: "Challenge", Status: "ACTIVE", Priority: 1, Actions: okta.PolicyRuleActions{Enroll: &okta.EnrollActions{Self: "CHALLENGE"}}}},
	}

	t.groups = []okta.Group{
		{ID: "g1", Type: "OKTA_GROUP", Created: kitNow.Add(-300 * day), Profile: okta.GroupProfile{Name: "Admins"}, Embedded: stats(2)},
		{ID: "g2", Type: "APP_GROUP", Created: kitNow.Add(-200 * day), Profile: okta.GroupProfile{Name: "Engineering"}, Embedded: stats(2)},
		{ID: "g3", Type: "BUILT_IN", Created: kitNow.Add(-400 * day), Profile: okta.GroupProfile{Name: "Everyone"}, Embedded: stats(6)},
	}
	t.groupUsers = map[string][]okta.User{
		"g1": {t.users[0], t.users[1]},
		"g2": {t.users[3], t.users[5]},
		"g3": t.users[:6],
	}

	t.authenticators = []okta.Authenticator{
		{Key: "okta_verify", Status: "ACTIVE"}, {Key: "webauthn", Status: "ACTIVE"},
		{Key: "okta_email", Status: "ACTIVE"}, {Key: "google_otp", Status: "INACTIVE"},
	}
	t.deviceAssurancePolicies = append(t.deviceAssurancePolicies, okta.DeviceAssurancePolicy{ID: "d2", Name: "macOS", Platform: "MACOS", Status: "ACTIVE"})
	t.networkZones = append(t.networkZones, okta.NetworkZone{ID: "z2", Name: "Blocked", Type: "IP", Status: "ACTIVE", Usage: "BLOCKLIST",
		Gateways: json.RawMessage(`[{"type":"RANGE","value":"203.0.113.1-203.0.113.9"}]`)})
	t.apiTokens = append(t.apiTokens, okta.APIToken{ID: "tok2", Name: "old-token", Status: "ACTIVE", Created: kitNow.Add(-300 * day), LastUpdated: kitNow.Add(-100 * day), UserID: "u2"})
	t.inlineHooks = []okta.InlineHook{{ID: "ih1", Name: "Token transform", Status: "INACTIVE", Type: "com.okta.oauth2.tokens.transform"}}
	t.systemLog = append(t.systemLog, okta.LogEvent{UUID: "e2", Published: kitNow.Add(-2 * day), EventType: "policy.lifecycle.update"})
	t.orgSettings = &okta.OrgSettings{ID: "00o-acme", Subdomain: "acme", Status: "ACTIVE"}
	t.orgContacts = []okta.OrgContact{{Type: "BILLING", UserID: "u1"}, {Type: "TECHNICAL", UserID: "u2"}}
	return t
}

// kitEmptyTenant has no users, apps, groups, or policies.
func kitEmptyTenant() *mockOktaClient {
	return &mockOktaClient{
		orgSettings:    &okta.OrgSettings{ID: "00o-empty", Subdomain: "empty", Status: "ACTIVE"},
		orgPreferences: &okta.OrgPreferences{SelfServiceUnlock: false},
		orgContacts:    []okta.OrgContact{{Type: "BILLING", UserID: "00u-departed"}, {Type: "TECHNICAL", UserID: "00u-departed"}},
	}
}

// kitResponses answers every call a clean internal-level run makes against
// tenant with an API token. URLs are the ones the client builds, query
// strings included.
func kitResponses(t *mockOktaClient) []collectortest.Response {
	me := collectortest.Response{URL: kitBase + "/api/v1/users/me", Body: kitJSON(map[string]any{"id": "u1", "status": "ACTIVE", "profile": map[string]any{"login": "alice@acme.com"}})}
	return append([]collectortest.Response{me}, kitSurfaceResponses(t)...)
}

// kitOAuthResponses is kitResponses for a service app, which signs in with
// the token exchange.
func kitOAuthResponses(t *mockOktaClient) []collectortest.Response {
	token := collectortest.Response{Method: http.MethodPost, URL: kitBase + "/oauth2/v1/token", Body: kitJSON(map[string]any{
		"token_type": "Bearer", "expires_in": 3600, "access_token": "kit-access-token-0123456789",
		"scope": "okta.users.read okta.groups.read okta.apps.read okta.policies.read okta.roles.read okta.deviceAssurance.read",
	})}
	return append([]collectortest.Response{token}, kitSurfaceResponses(t)...)
}

func kitSurfaceResponses(t *mockOktaClient) []collectortest.Response {
	listed := func(path string) string { return kitBase + path + "?limit=200" }
	responses := kitUserPages(t.users)

	for _, u := range t.users {
		responses = append(responses,
			collectortest.Response{URL: kitBase + "/api/v1/users/" + u.ID + "/factors", Body: kitList(t.factors[u.ID])},
			collectortest.Response{URL: kitBase + "/api/v1/users/" + u.ID + "/groups", Body: kitList(kitGroupRefs(t.userGroupIDs[u.ID]))},
		)
	}
	responses = append(responses, collectortest.Response{URL: listed("/api/v1/iam/assignees/users"), Body: kitJSON(map[string]any{"value": nonNil(t.roleAssignees)})})
	for _, a := range t.roleAssignees {
		responses = append(responses, collectortest.Response{URL: kitBase + "/api/v1/users/" + a.ID + "/roles", Body: kitList(t.userRoles[a.ID])})
	}
	responses = append(responses, collectortest.Response{URL: listed("/api/v1/iam/roles"), Body: kitJSON(map[string]any{"roles": nonNil(t.iamRoles)})})
	for _, r := range t.iamRoles {
		var permissions []map[string]string
		for _, label := range t.rolePermissions[r.ID] {
			permissions = append(permissions, map[string]string{"label": label})
		}
		responses = append(responses, collectortest.Response{URL: kitBase + "/api/v1/iam/roles/" + r.ID + "/permissions", Body: kitJSON(map[string]any{"permissions": nonNil(permissions)})})
	}

	responses = append(responses, collectortest.Response{URL: listed("/api/v1/apps"), Body: kitList(t.apps)})
	for _, policyType := range []string{PolicyTypeSignOn, PolicyTypeMFAEnroll} {
		responses = append(responses, collectortest.Response{URL: kitBase + "/api/v1/policies?type=" + policyType, Body: kitList(t.policies[policyType])})
		for _, p := range t.policies[policyType] {
			responses = append(responses, collectortest.Response{URL: kitBase + "/api/v1/policies/" + p.ID + "/rules", Body: kitList(t.policyRules[p.ID])})
		}
	}
	responses = append(responses, collectortest.Response{URL: kitBase + "/api/v1/groups?expand=stats&limit=200", Body: kitList(t.groups)})
	for _, g := range t.groups {
		responses = append(responses, collectortest.Response{URL: kitBase + "/api/v1/groups/" + g.ID + "/users?limit=200", Body: kitList(t.groupUsers[g.ID])})
	}

	logQuery := url.Values{}
	logQuery.Set("since", kitNow.Add(-systemLogWindow).Format(time.RFC3339))
	logQuery.Set("sortOrder", "DESCENDING")
	logQuery.Set("limit", "200")
	logQuery.Set("filter", buildSystemLogFilter())

	responses = append(responses,
		collectortest.Response{URL: kitBase + "/api/v1/device-assurances", Body: kitList(t.deviceAssurancePolicies)},
		collectortest.Response{URL: kitBase + "/api/v1/authenticators", Body: kitList(t.authenticators)},
		collectortest.Response{URL: listed("/api/v1/zones"), Body: kitList(t.networkZones)},
		collectortest.Response{URL: listed("/api/v1/idps"), Body: kitList(t.identityProviders)},
		collectortest.Response{URL: kitBase + "/api/v1/api-tokens", Body: kitList(t.apiTokens)},
		collectortest.Response{URL: kitBase + "/api/v1/eventHooks", Body: kitList(t.eventHooks)},
		collectortest.Response{URL: kitBase + "/api/v1/inlineHooks", Body: kitList(t.inlineHooks)},
		collectortest.Response{URL: kitBase + "/api/v1/logs?" + logQuery.Encode(), Body: kitList(t.systemLog)},
		collectortest.Response{URL: kitBase + "/api/v1/org", Body: kitJSON(t.orgSettings)},
		collectortest.Response{URL: kitBase + "/api/v1/org/preferences", Body: kitJSON(map[string]any{"showEndUserFooter": true, "selfServiceUnlock": t.orgPreferences.SelfServiceUnlock})},
	)
	for _, contact := range t.orgContacts {
		responses = append(responses, collectortest.Response{URL: kitBase + "/api/v1/org/contacts/" + contact.Type, Body: kitJSON(map[string]any{"userId": contact.UserID})})
	}
	return responses
}

// kitUserPages lists users over two pages joined by a Link header, as Okta
// pages them.
func kitUserPages(users []okta.User) []collectortest.Response {
	first := kitBase + "/api/v1/users?limit=200"
	if len(users) < 2 {
		return []collectortest.Response{{URL: first, Body: kitList(users)}}
	}
	split := (len(users) + 1) / 2
	cursor := users[split-1].ID
	second := kitBase + "/api/v1/users?after=" + cursor + "&limit=200"
	return []collectortest.Response{
		{URL: first, Body: kitList(users[:split]), Header: http.Header{"Link": []string{
			"<" + first + `>; rel="self", <` + second + `>; rel="next"`,
		}}},
		{URL: second, Body: kitList(users[split:])},
	}
}

func kitGroupRefs(ids []string) []okta.Group {
	groups := make([]okta.Group, 0, len(ids))
	for _, id := range ids {
		groups = append(groups, okta.Group{ID: id})
	}
	return groups
}

// kitList renders a list as JSON, with a nil slice as the empty list Okta
// sends rather than null.
func kitList[T any](items []T) string {
	return kitJSON(nonNil(items))
}

func nonNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

func kitJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("kit fixture: %v", err))
	}
	return string(raw)
}

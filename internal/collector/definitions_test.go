package collector

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// These tests check the values the idp-posture schema defines: user_count
// counts enabled accounts, privileged users hold a role that can change
// access, MFA requirements count blocked sign-ins as covered, and named
// exceptions do not make mfa_required false.

var defNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// defRun collects client's org at level and returns both artifacts as JSON
// documents, with the code of each gap by its artifact path and pointer.
func defRun(t *testing.T, client *mockOktaClient, level componentsdk.Level) (detailedDoc, normalizedDoc map[string]any, gaps map[string]componentsdk.Code) {
	t.Helper()
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{OrgDomain: "acme.okta.com", Recorder: rec, Now: func() time.Time { return defNow }}, client)
	posture, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	c.Artifacts(posture)
	gaps = map[string]componentsdk.Code{}
	for _, g := range rec.Gaps() {
		gaps[g.Path+"#"+g.Pointer] = g.Code
	}
	return asDoc(t, posture), asDoc(t, posture.ToIDPPosture()), gaps
}

func asDoc(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// at returns the value at a two-level pointer such as "users/total_count",
// and whether it is there.
func at(doc map[string]any, section, field string) (any, bool) {
	s, ok := doc[section].(map[string]any)
	if !ok {
		return nil, false
	}
	v, ok := s[field]
	return v, ok
}

// wantValues checks each "section/field" of doc against its want, where a
// number is compared as a float and nil means null.
func wantValues(t *testing.T, name string, doc map[string]any, want map[[2]string]any) {
	t.Helper()
	for path, w := range want {
		got, ok := at(doc, path[0], path[1])
		if !ok {
			t.Errorf("%s /%s/%s left out, want %v", name, path[0], path[1], w)
			continue
		}
		if n, isInt := w.(int); isInt {
			w = float64(n)
		}
		if got != w {
			t.Errorf("%s /%s/%s = %v, want %v", name, path[0], path[1], got, w)
		}
	}
}

func defUser(id, status string, daysSinceSignIn int) okta.User {
	u := okta.User{ID: id, Status: status, Created: defNow.AddDate(-1, 0, 0), Profile: okta.UserProfile{Login: id + "@acme.com"}}
	if daysSinceSignIn >= 0 {
		u.LastLogin = defNow.AddDate(0, 0, -daysSinceSignIn)
	}
	return u
}

func defFactor(factorType string) okta.Factor {
	return okta.Factor{ID: "f-" + factorType, FactorType: factorType, Status: StatusActive, Created: defNow.AddDate(0, -1, 0)}
}

func everyoneGroup(include ...string) *okta.PolicyPeopleCondition {
	return peopleGroups(include, nil)
}

// defOrg is an org whose one sign-on policy, for the Everyone group, has
// the given rules.
func defOrg(users []okta.User, rules ...okta.PolicyRule) *mockOktaClient {
	return &mockOktaClient{
		users:      users,
		factors:    map[string][]okta.Factor{},
		groupUsers: map[string][]okta.User{"everyone": users},
		policies: map[string][]okta.Policy{PolicyTypeSignOn: {{
			ID: "gsp", Name: "Default", Type: PolicyTypeSignOn, Status: StatusActive, Priority: 1,
			Conditions: okta.PolicyConditions{People: everyoneGroup("everyone")},
		}}},
		policyRules: map[string][]okta.PolicyRule{"gsp": rules},
	}
}

func mfaRule(name string) okta.PolicyRule {
	return okta.PolicyRule{ID: name, Name: name, Status: StatusActive, Priority: intPtr(1), Actions: okta.PolicyRuleActions{Signon: &okta.SignonActions{Access: AccessAllow, RequireFactor: true}}}
}

func openRule(name string) okta.PolicyRule {
	return okta.PolicyRule{ID: name, Name: name, Status: StatusActive, Priority: intPtr(99), Actions: okta.PolicyRuleActions{Signon: &okta.SignonActions{Access: AccessAllow}}}
}

func denyRule(name string) okta.PolicyRule {
	return okta.PolicyRule{ID: name, Name: name, Status: StatusActive, Priority: intPtr(99), Actions: okta.PolicyRuleActions{Signon: &okta.SignonActions{Access: AccessDeny}}}
}

// TestUserCount_CountsEnabledAccounts checks that user_count and the values
// over it count only enabled accounts, and lifecycle.account_count every
// account Okta lists.
func TestUserCount_CountsEnabledAccounts(t *testing.T) {
	users := []okta.User{
		defUser("active", "ACTIVE", 1),
		defUser("expired", "PASSWORD_EXPIRED", 2),
		defUser("locked", "LOCKED_OUT", 200),
		defUser("recovery", "RECOVERY", -1),
		defUser("suspended", "SUSPENDED", 300),
		defUser("staged", "STAGED", -1),
		defUser("provisioned", "PROVISIONED", -1),
	}
	client := defOrg(users, mfaRule("mfa"))
	client.factors = map[string][]okta.Factor{
		"active":    {defFactor("push")},
		"locked":    {defFactor("webauthn")},
		"suspended": {defFactor("webauthn")},
		"staged":    {defFactor("push")},
	}
	detailedDoc, normalized, _ := defRun(t, client, componentsdk.LevelAudit)

	wantValues(t, "detailed", detailedDoc, map[[2]string]any{
		{"users", "total_count"}:                     7,
		{"users", "enabled_count"}:                   4,
		{"users", "inactive_count"}:                  2,
		{"users", "inactive"}:                        50,
		{"users", "locked_out"}:                      25,
		{"users", "password_expired"}:                25,
		{"users", "suspended_count"}:                 1,
		{"users", "suspended"}:                       14,
		{"posture", "mfa_enrolled_users_count"}:      2,
		{"posture", "mfa_coverage"}:                  50,
		{"posture", "mfa_phishing_resistant"}:        25,
		{"posture", "mfa_disabled_users_count"}:      2,
		{"policy", "mfa_required_users_count"}:       4,
		{"policy", "mfa_required_coverage_pct"}:      100,
		{"policy", "mfa_required_all"}:               true,
		{"device_access", "managed_device_required"}: false,
	})
	wantValues(t, "normalized", normalized, map[[2]string]any{
		{"user_security", "user_count"}:                    4,
		{"user_security", "mfa_user_count"}:                2,
		{"user_security", "phishing_resistant_user_count"}: 1,
		{"user_security", "inactive_user_count"}:           2,
		{"user_security", "inactive_pct"}:                  50,
		{"user_security", "mfa_coverage_pct"}:              50,
		{"lifecycle", "account_count"}:                     7,
		{"lifecycle", "suspended_account_count"}:           1,
		{"lifecycle", "suspended_pct"}:                     15,
		{"policy", "mfa_required_user_count"}:              4,
		{"policy", "mfa_required_coverage_pct"}:            100,
		{"policy", "mfa_required"}:                         true,
	})
}

// TestUserCount_OnlySuspendedAccounts checks an org whose accounts are all
// suspended: no users to take shares of, and every account suspended.
func TestUserCount_OnlySuspendedAccounts(t *testing.T) {
	users := []okta.User{defUser("s1", "SUSPENDED", 5), defUser("s2", "SUSPENDED", 5)}
	_, normalized, _ := defRun(t, defOrg(users, mfaRule("mfa")), componentsdk.LevelAudit)
	wantValues(t, "normalized", normalized, map[[2]string]any{
		{"user_security", "users_present"}:      false,
		{"user_security", "user_count"}:         0,
		{"user_security", "mfa_coverage_pct"}:   nil,
		{"lifecycle", "accounts_present"}:       true,
		{"lifecycle", "account_count"}:          2,
		{"lifecycle", "suspended_pct"}:          100,
		{"policy", "mfa_required_coverage_pct"}: nil,
	})
}

// adminOrg is an org of the given users, each holding the roles Okta lists
// for them, with the given custom roles' permissions.
func adminOrg(users []okta.User, roles map[string][]okta.RoleAssignment, permissions map[string][]string) *mockOktaClient {
	client := defOrg(users, mfaRule("mfa"))
	for _, u := range users {
		client.roleAssignees = append(client.roleAssignees, okta.RoleAssignedUser{ID: u.ID})
		client.factors[u.ID] = []okta.Factor{defFactor("webauthn")}
	}
	client.userRoles = roles
	client.rolePermissions = permissions
	return client
}

func role(roleType string) okta.RoleAssignment {
	return okta.RoleAssignment{ID: "ra-" + roleType, Type: roleType, Label: roleType, AssignmentType: "USER"}
}

func customRole(roleID, label string) okta.RoleAssignment {
	return okta.RoleAssignment{ID: "ra-" + roleID, Type: "CUSTOM", Role: roleID, Label: label, AssignmentType: "USER"}
}

// TestPrivileged_CountsRolesThatCanChangeAccess checks that the privileged
// count leaves out roles that can only read and accounts that are not
// enabled, and counts a custom role only when it grants a write.
func TestPrivileged_CountsRolesThatCanChangeAccess(t *testing.T) {
	users := []okta.User{
		defUser("readonly", "ACTIVE", 1),
		defUser("report", "ACTIVE", 1),
		defUser("mobile", "ACTIVE", 1),
		defUser("apiam", "ACTIVE", 1),
		defUser("staged-super", "STAGED", -1),
		defUser("custom-read", "ACTIVE", 1),
		defUser("custom-write", "ACTIVE", 1),
		defUser("custom-factors", "ACTIVE", 1),
		defUser("readonly-and-custom-read", "ACTIVE", 1),
	}
	roles := map[string][]okta.RoleAssignment{
		"readonly":                 {role("READ_ONLY_ADMIN")},
		"report":                   {role("REPORT_ADMIN")},
		"mobile":                   {role("MOBILE_ADMIN")},
		"apiam":                    {role("API_ACCESS_MANAGEMENT_ADMIN")},
		"staged-super":             {role("SUPER_ADMIN")},
		"custom-read":              {customRole("cr-read", "Auditor")},
		"custom-write":             {customRole("cr-groups", "Group Manager")},
		"custom-factors":           {customRole("cr-factors", "Factor Reset")},
		"readonly-and-custom-read": {role("READ_ONLY_ADMIN"), customRole("cr-read", "Auditor")},
	}
	permissions := map[string][]string{
		"cr-read":    {"okta.users.read", "okta.groups.read", "okta.apps.read"},
		"cr-groups":  {"okta.groups.read", "okta.groups.members.manage"},
		"cr-factors": {"okta.users.read", "okta.users.credentials.resetFactors"},
	}
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		t.Run(string(level), func(t *testing.T) {
			detailedDoc, normalized, _ := defRun(t, adminOrg(users, roles, permissions), level)
			wantValues(t, "detailed", detailedDoc, map[[2]string]any{
				{"privileged_access", "privileged_users_count"}:          4,
				{"privileged_access", "standing_privileged_users_count"}: 4,
				{"privileged_access", "super_admin_count"}:               0,
				{"privileged_access", "privileged_mfa_enrolled_count"}:   4,
			})
			wantValues(t, "normalized", normalized, map[[2]string]any{
				{"privileged_access", "privileged_users_present"}: true,
			})
			if level != componentsdk.LevelAudit {
				return
			}
			rows, _ := at(detailedDoc, "privileged_access", "inventory")
			var logins []string
			for _, row := range rows.([]any) {
				logins = append(logins, row.(map[string]any)["login"].(string))
			}
			want := []string{"mobile@acme.com", "apiam@acme.com", "custom-write@acme.com", "custom-factors@acme.com"}
			if len(logins) != len(want) {
				t.Fatalf("inventory logins = %v, want %v", logins, want)
			}
			for i := range want {
				if logins[i] != want[i] {
					t.Errorf("inventory logins = %v, want %v", logins, want)
					break
				}
			}
		})
	}
}

// TestPrivileged_CountsRolesThatManageSignIn checks that a custom role that
// can manage identity providers or authorization servers counts as
// privileged, since either changes who can sign in and how.
func TestPrivileged_CountsRolesThatManageSignIn(t *testing.T) {
	users := []okta.User{defUser("idp", "ACTIVE", 1), defUser("authz", "ACTIVE", 1), defUser("readers", "ACTIVE", 1)}
	roles := map[string][]okta.RoleAssignment{
		"idp":     {customRole("cr-idp", "Identity Provider Manager")},
		"authz":   {customRole("cr-authz", "Authorization Server Manager")},
		"readers": {customRole("cr-read", "Sign-in Auditor")},
	}
	permissions := map[string][]string{
		"cr-idp":   {"okta.identityProviders.read", "okta.identityProviders.manage"},
		"cr-authz": {"okta.authzServers.read", "okta.authzServers.manage"},
		"cr-read":  {"okta.identityProviders.read", "okta.authzServers.read"},
	}
	detailedDoc, _, _ := defRun(t, adminOrg(users, roles, permissions), componentsdk.LevelTrust)
	wantValues(t, "detailed", detailedDoc, map[[2]string]any{{"privileged_access", "privileged_users_count"}: 2})
}

// TestPrivileged_UnreadCustomRoleLeavesCountsOut checks that a custom role
// whose permissions cannot be read leaves the privileged counts out with a
// partial gap, rather than counting its holder either way.
func TestPrivileged_UnreadCustomRoleLeavesCountsOut(t *testing.T) {
	users := []okta.User{defUser("super", "ACTIVE", 1), defUser("custom", "ACTIVE", 1)}
	client := adminOrg(users, map[string][]okta.RoleAssignment{
		"super":  {role("SUPER_ADMIN")},
		"custom": {customRole("cr1", "Help Desk")},
	}, nil)
	client.rolePermissionsErr = &okta.APIStatusError{StatusCode: 500, Path: "/api/v1/iam/roles/cr1/permissions"}
	detailedDoc, _, gaps := defRun(t, client, componentsdk.LevelTrust)
	if v, ok := at(detailedDoc, "privileged_access", "privileged_users_count"); !ok || v != nil {
		t.Errorf("privileged_users_count = %v, want null", v)
	}
	if code := gaps[detailedPath+"#/privileged_access/privileged_users_count"]; code == "" {
		t.Error("privileged_users_count has no gap")
	}
}

// TestMFA_SecurityQuestionIsNotMFA checks that a security question factor
// does not count as MFA.
func TestMFA_SecurityQuestionIsNotMFA(t *testing.T) {
	users := []okta.User{defUser("question", "ACTIVE", 1), defUser("question-and-push", "ACTIVE", 1)}
	client := defOrg(users, mfaRule("mfa"))
	client.factors = map[string][]okta.Factor{
		"question":          {defFactor("question")},
		"question-and-push": {defFactor("question"), defFactor("push")},
	}
	detailedDoc, _, _ := defRun(t, client, componentsdk.LevelTrust)
	wantValues(t, "detailed", detailedDoc, map[[2]string]any{
		{"posture", "mfa_enrolled_users_count"}: 1,
		{"posture", "mfa_coverage"}:             50,
	})
}

// TestMFARequired_DenyRuleCovers checks that a rule that blocks sign-in
// counts as covered, since a blocked sign-in cannot skip MFA.
func TestMFARequired_DenyRuleCovers(t *testing.T) {
	users := []okta.User{defUser("a", "ACTIVE", 1), defUser("b", "ACTIVE", 1)}
	deny := denyRule("deny")
	deny.Conditions.People = peopleUsers([]string{"b"}, nil)
	deny.Priority = intPtr(1)
	client := defOrg(users, deny, mfaRule("mfa"))
	client.policyRules["gsp"][1].Priority = intPtr(2)
	detailedDoc, normalized, _ := defRun(t, client, componentsdk.LevelAudit)
	wantValues(t, "detailed", detailedDoc, map[[2]string]any{
		{"policy", "mfa_required_users_count"}: 2,
		{"policy", "mfa_required_all"}:         true,
	})
	wantValues(t, "normalized", normalized, map[[2]string]any{{"policy", "mfa_required"}: true})
}

// managedDeviceRule lets in sign-ins from managed devices, requiring MFA
// when mfa is set. It is a Classic Engine sign-on rule.
func managedDeviceRule(mfa bool) okta.PolicyRule {
	r := okta.PolicyRule{ID: "managed", Name: "Managed devices", Status: StatusActive, Priority: intPtr(1),
		Conditions: okta.PolicyRuleConditions{Device: &okta.DeviceCondition{Managed: "true"}},
		Actions:    okta.PolicyRuleActions{Signon: &okta.SignonActions{Access: AccessAllow, RequireFactor: mfa}}}
	return r
}

// TestManagedDeviceCondition_LimitsTheRule checks that a rule limited to
// managed devices settles only those sign-ins, for MFA and for the
// managed-device requirement.
func TestManagedDeviceCondition_LimitsTheRule(t *testing.T) {
	users := []okta.User{defUser("a", "ACTIVE", 1), defUser("b", "ACTIVE", 1)}
	cases := []struct {
		name                     string
		catchAll                 okta.PolicyRule
		mfaCovered, deviceNeeded bool
	}{
		{"other devices get in without MFA", openRule("open"), false, false},
		{"other devices must use MFA", func() okta.PolicyRule { r := mfaRule("mfa"); r.Priority = intPtr(99); return r }(), true, false},
		{"other devices are blocked", denyRule("deny"), true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detailedDoc, normalized, _ := defRun(t, defOrg(users, managedDeviceRule(true), tc.catchAll), componentsdk.LevelAudit)
			covered := 0
			if tc.mfaCovered {
				covered = 2
			}
			needed := 0
			if tc.deviceNeeded {
				needed = 2
			}
			wantValues(t, "detailed", detailedDoc, map[[2]string]any{
				{"policy", "mfa_required_users_count"}:                   covered,
				{"device_access", "managed_device_required_users_count"}: needed,
				{"device_access", "managed_device_required"}:             tc.deviceNeeded,
			})
			_, written := normalized["device_access"]
			if written != tc.deviceNeeded {
				t.Errorf("normalized device_access written = %v, want %v", written, tc.deviceNeeded)
			}
		})
	}
}

func networkRule(name, connection string, include, exclude []string, signon *okta.SignonActions) okta.PolicyRule {
	r := okta.PolicyRule{ID: name, Name: name, Status: StatusActive, Priority: intPtr(1), Actions: okta.PolicyRuleActions{Signon: signon}}
	r.Conditions.Network = &struct {
		Connection string   `json:"connection"`
		Include    []string `json:"include,omitempty"`
		Exclude    []string `json:"exclude,omitempty"`
	}{Connection: connection, Include: include, Exclude: exclude}
	return r
}

// TestMFARequired_LimitedRulesTogether checks that limited rules that
// together settle every sign-in count as covering, and those that leave
// some out do not.
func TestMFARequired_LimitedRulesTogether(t *testing.T) {
	users := []okta.User{defUser("a", "ACTIVE", 1)}
	mfa := func() *okta.SignonActions { return &okta.SignonActions{Access: AccessAllow, RequireFactor: true} }
	deny := func() *okta.SignonActions { return &okta.SignonActions{Access: AccessDeny} }
	cases := []struct {
		name  string
		rules []okta.PolicyRule
		want  int
	}{
		{"on and off network", []okta.PolicyRule{networkRule("on", "ON_NETWORK", nil, nil, mfa()), networkRule("off", "OFF_NETWORK", nil, nil, mfa())}, 1},
		{"in a zone, and outside it blocked", []okta.PolicyRule{networkRule("in", "ZONE", []string{"z1"}, nil, mfa()), networkRule("out", "ZONE", nil, []string{"z1"}, deny())}, 1},
		{"outside each of two zones", []okta.PolicyRule{networkRule("x1", "ZONE", nil, []string{"z1"}, mfa()), networkRule("x2", "ZONE", nil, []string{"z2"}, mfa())}, 1},
		{"in two zones only", []okta.PolicyRule{networkRule("z1", "ZONE", []string{"z1"}, nil, mfa()), networkRule("z2", "ZONE", []string{"z2"}, nil, mfa())}, 0},
		{"on network only", []okta.PolicyRule{networkRule("on", "ON_NETWORK", nil, nil, mfa())}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := append(tc.rules, openRule("open"))
			for i := range rules {
				rules[i].Priority = intPtr(i + 1)
			}
			detailedDoc, _, _ := defRun(t, defOrg(users, rules...), componentsdk.LevelTrust)
			wantValues(t, "detailed", detailedDoc, map[[2]string]any{{"policy", "mfa_required_users_count"}: tc.want})
		})
	}
}

// TestMFARequired_EnrollmentLoginIsNotARequirement checks that an MFA
// enrollment rule set to LOGIN, which has people enroll once, does not
// count as requiring MFA at sign-in.
func TestMFARequired_EnrollmentLoginIsNotARequirement(t *testing.T) {
	users := []okta.User{defUser("a", "ACTIVE", 1)}
	client := defOrg(users, openRule("open"))
	client.policies[PolicyTypeMFAEnroll] = []okta.Policy{{ID: "enroll", Name: "Enroll", Type: PolicyTypeMFAEnroll, Status: StatusActive, Priority: 1,
		Conditions: okta.PolicyConditions{People: everyoneGroup("everyone")}}}
	client.policyRules["enroll"] = []okta.PolicyRule{{ID: "login", Status: StatusActive, Priority: intPtr(1), Actions: okta.PolicyRuleActions{Enroll: &okta.EnrollActions{Self: "LOGIN"}}}}
	detailedDoc, _, _ := defRun(t, client, componentsdk.LevelTrust)
	wantValues(t, "detailed", detailedDoc, map[[2]string]any{
		{"policy", "mfa_required_users_count"}: 0,
		{"policy", "mfa_required_all"}:         false,
	})
}

// TestMFARequired_NamedExceptions checks that users and groups a rule or
// policy excludes by name do not make mfa_required false, and still count
// as not covered.
func TestMFARequired_NamedExceptions(t *testing.T) {
	users := []okta.User{defUser("a", "ACTIVE", 1), defUser("b", "ACTIVE", 1), defUser("breakglass", "ACTIVE", 1), defUser("ops", "ACTIVE", 1)}
	excludeByUser := mfaRule("mfa")
	excludeByUser.Conditions.People = peopleUsers(nil, []string{"breakglass"})
	byGroup := defOrg(users, mfaRule("mfa"), openRule("open"))
	byGroup.policies[PolicyTypeSignOn][0].Conditions.People = peopleGroups([]string{"everyone"}, []string{"emergency"})
	byGroup.groupUsers["emergency"] = []okta.User{users[2], users[3]}
	byGroup.policies[PolicyTypeSignOn] = append(byGroup.policies[PolicyTypeSignOn], okta.Policy{ID: "fallback", Name: "Fallback", Type: PolicyTypeSignOn, Status: StatusActive, Priority: 2,
		Conditions: okta.PolicyConditions{People: everyoneGroup("everyone")}})
	byGroup.policyRules["fallback"] = []okta.PolicyRule{openRule("open")}
	scoped := defOrg(users, mfaRule("mfa"))
	scoped.policies[PolicyTypeSignOn][0].Conditions.People = everyoneGroup("staff")
	scoped.groupUsers["staff"] = users[:2]

	cases := []struct {
		name     string
		client   *mockOktaClient
		required bool
		count    int
	}{
		{"user excluded from the MFA rule", defOrg(users, excludeByUser, openRule("open")), true, 3},
		{"group excluded from the MFA policy", byGroup, true, 2},
		{"policy scoped to some groups", scoped, false, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detailedDoc, normalized, _ := defRun(t, tc.client, componentsdk.LevelAudit)
			wantValues(t, "detailed", detailedDoc, map[[2]string]any{
				{"policy", "mfa_required_users_count"}: tc.count,
				{"policy", "mfa_required_all"}:         false,
			})
			wantValues(t, "normalized", normalized, map[[2]string]any{
				{"policy", "mfa_required"}:            tc.required,
				{"policy", "mfa_required_user_count"}: tc.count,
			})
		})
	}
}

// TestMFARequired_NamedExceptionsUnderAppSignInPolicies checks that with an
// excluded user and an app sign-in policy, mfa_required is written, since
// an app sign-in policy can only add to it, while the count and share are
// left out, since it can cover the excluded user.
func TestMFARequired_NamedExceptionsUnderAppSignInPolicies(t *testing.T) {
	users := []okta.User{defUser("a", "ACTIVE", 1), defUser("breakglass", "ACTIVE", 1)}
	excludeByUser := mfaRule("mfa")
	excludeByUser.Conditions.People = peopleUsers(nil, []string{"breakglass"})
	client := defOrg(users, excludeByUser, openRule("open"))
	client.apps = []okta.Application{appWithSignInPolicy("app1", "rst1")}
	_, normalized, gaps := defRun(t, client, componentsdk.LevelAudit)
	wantValues(t, "normalized", normalized, map[[2]string]any{{"policy", "mfa_required"}: true})
	for _, pointer := range []string{"/policy/mfa_required_coverage_pct", "/policy/mfa_required_user_count"} {
		if _, ok := at(normalized, "policy", pointer[len("/policy/"):]); ok {
			t.Errorf("%s written, want left out", pointer)
		}
		if code := gaps[idpPosturePath+"#"+pointer]; code != componentsdk.CodeNotRead {
			t.Errorf("%s gap = %q, want not_read", pointer, code)
		}
	}
	if code, ok := gaps[idpPosturePath+"#/policy/mfa_required"]; ok {
		t.Errorf("mfa_required has a %s gap, want none", code)
	}
}

// TestLegacyAuthBlocked_LeftOutWithAGap checks that legacy_auth_blocked,
// which the collector does not read, is left out with a not_read gap.
func TestLegacyAuthBlocked_LeftOutWithAGap(t *testing.T) {
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		_, _, gaps := defRun(t, defOrg([]okta.User{defUser("a", "ACTIVE", 1)}, mfaRule("mfa")), level)
		if code := gaps[idpPosturePath+"#/policy/legacy_auth_blocked"]; code != componentsdk.CodeNotRead {
			t.Errorf("%s: legacy_auth_blocked gap = %q, want not_read", level, code)
		}
	}
}

// TestRulePriority_NullSortsLast checks that a rule Okta lists with no
// priority is evaluated after the rules that have one, as Okta does, and
// that its row has no priority.
func TestRulePriority_NullSortsLast(t *testing.T) {
	var rules []okta.PolicyRule
	if err := json.Unmarshal([]byte(`[
		{"id":"open","name":"Catch-all","status":"ACTIVE","priority":null,"actions":{"signon":{"access":"ALLOW","requireFactor":false}}},
		{"id":"mfa","name":"MFA","status":"ACTIVE","priority":1,"actions":{"signon":{"access":"ALLOW","requireFactor":true}}}
	]`), &rules); err != nil {
		t.Fatal(err)
	}
	detailedDoc, _, _ := defRun(t, defOrg([]okta.User{defUser("a", "ACTIVE", 1)}, rules...), componentsdk.LevelInternal)
	wantValues(t, "detailed", detailedDoc, map[[2]string]any{{"policy", "mfa_required_users_count"}: 1})
	policies, _ := at(detailedDoc, "policy", "policies")
	ruleRows := policies.([]any)[0].(map[string]any)["rules"].([]any)
	last := ruleRows[len(ruleRows)-1].(map[string]any)
	if last["name"] != "Catch-all" {
		t.Errorf("last rule = %v, want Catch-all", last["name"])
	}
	if p, ok := last["priority"]; ok {
		t.Errorf("Catch-all priority = %v, want left out", p)
	}
}

package collector

import (
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// These tests check who signs in through another identity provider, which
// decides whether they use MFA, so the idp-posture MFA values are left out.

var defPartner = okta.IdentityProvider{ID: "0oapartner", Name: "Partner SAML", Type: "SAML2", Status: "ACTIVE"}

// routeRule is an active routing rule at priority that sends the users cond
// matches to the providers of types, each with the partner's ID.
func routeRule(priority int, cond *okta.UserIdentifierCondition, types ...string) okta.PolicyRule {
	rule := okta.PolicyRule{ID: "route", Status: StatusActive, Priority: intPtr(priority), Type: PolicyTypeIdPDiscovery}
	rule.Conditions.UserIdentifier = cond
	rule.Actions.IDP = &okta.RoutingAction{IdpSelectionType: "SPECIFIC"}
	for _, kind := range types {
		rule.Actions.IDP.Providers = append(rule.Actions.IDP.Providers, okta.RoutingProvider{Type: kind, ID: defPartner.ID})
	}
	return rule
}

func identifier(kind, attribute, matchType, value string) *okta.UserIdentifierCondition {
	return &okta.UserIdentifierCondition{Type: kind, Attribute: attribute, Patterns: []okta.UserIdentifierPattern{{MatchType: matchType, Value: value}}}
}

func TestRoutingElsewhere(t *testing.T) {
	user := defUser("ana", StatusActive, 1)
	federated := user
	federated.Credentials.Provider.Type = "FEDERATION"
	emailed := user
	emailed.Profile.Email = "ana@partner.example"
	login := func(matchType, value string) *okta.UserIdentifierCondition {
		return identifier("IDENTIFIER", "", matchType, value)
	}
	onNetwork := func(rule okta.PolicyRule) okta.PolicyRule {
		rule.Conditions.Network = &struct {
			Connection string   `json:"connection"`
			Include    []string `json:"include,omitempty"`
			Exclude    []string `json:"exclude,omitempty"`
		}{Connection: "ZONE", Include: []string{"office"}}
		return rule
	}
	dynamic := routeRule(1, nil)
	dynamic.Actions.IDP.IdpSelectionType = "DYNAMIC"
	for _, tc := range []struct {
		name  string
		rules []okta.PolicyRule
		user  okta.User
		want  []string
	}{
		{"no routing rule", nil, user, nil},
		{"the domain", []okta.PolicyRule{routeRule(1, login("SUFFIX", "acme.com"), "SAML2")}, user, []string{"Partner SAML"}},
		{"another domain", []okta.PolicyRule{routeRule(1, login("SUFFIX", "partner.example"), "SAML2")}, user, nil},
		{"the login in another case", []okta.PolicyRule{routeRule(1, login("EQUALS", "ANA@acme.com"), "SAML2")}, user, []string{"Partner SAML"}},
		{"a prefix", []okta.PolicyRule{routeRule(1, login("STARTS_WITH", "ana@"), "SAML2")}, user, []string{"Partner SAML"}},
		{"a part", []okta.PolicyRule{routeRule(1, login("CONTAINS", "@acme"), "SAML2")}, user, []string{"Partner SAML"}},
		{"an expression", []okta.PolicyRule{routeRule(1, login("EXPRESSION", `^[a-z]+@acme\.com$`), "SAML2")}, user, []string{"Partner SAML"}},
		{"an expression that doesn't match", []okta.PolicyRule{routeRule(1, login("EXPRESSION", `^bo@`), "SAML2")}, user, nil},
		{"an expression Go can't compile", []okta.PolicyRule{routeRule(1, login("EXPRESSION", `(?<=x)a`), "SAML2")}, user, []string{"Partner SAML"}},
		{"an attribute the collector doesn't read", []okta.PolicyRule{routeRule(1, identifier("ATTRIBUTE", "department", "EQUALS", "Sales"), "SAML2")}, user, []string{"Partner SAML"}},
		{"an email that differs", []okta.PolicyRule{routeRule(1, identifier("ATTRIBUTE", "email", "SUFFIX", "partner.example"), "SAML2")}, user, nil},
		{"an email that matches", []okta.PolicyRule{routeRule(1, identifier("ATTRIBUTE", "email", "SUFFIX", "partner.example"), "SAML2")}, emailed, []string{"Partner SAML"}},
		{"everyone", []okta.PolicyRule{routeRule(1, nil, "SAML2")}, user, []string{"Partner SAML"}},
		{"an earlier rule to Okta", []okta.PolicyRule{routeRule(1, nil, "OKTA"), routeRule(2, nil, "SAML2")}, user, nil},
		{"an earlier rule to Okta on one network", []okta.PolicyRule{onNetwork(routeRule(1, nil, "OKTA")), routeRule(2, nil, "SAML2")}, user, []string{"Partner SAML"}},
		{"a choice of Okta and the partner", []okta.PolicyRule{routeRule(1, nil, "OKTA", "SAML2")}, user, []string{"Partner SAML"}},
		{"Okta's desktop sign-on and smart cards", []okta.PolicyRule{routeRule(1, nil, "IWA", "AgentlessDSSO", "X509")}, user, nil},
		{"a provider picked by expression", []okta.PolicyRule{dynamic}, user, []string{dynamicRoute}},
		{"no password and no rule", nil, federated, []string{"Partner SAML"}},
		{"no password and a rule to Okta", []okta.PolicyRule{routeRule(1, nil, "OKTA")}, federated, []string{"Partner SAML"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := routing{rules: tc.rules, idps: []okta.IdentityProvider{defPartner}}.elsewhere(tc.user)
			if !slices.Equal(got, tc.want) {
				t.Errorf("elsewhere = %q, want %q", got, tc.want)
			}
		})
	}
}

// routedOrg is defOrg with an IdP routing rule that sends acme.com to the
// partner, the partner listed, and each user with an email factor.
func routedOrg(users []okta.User) *mockOktaClient {
	client := defOrg(users, mfaRule("mfa"))
	client.policies[PolicyTypeIdPDiscovery] = []okta.Policy{{ID: "routing", Name: "Idp Discovery Policy", Type: PolicyTypeIdPDiscovery, Status: StatusActive, Priority: 1, System: true}}
	client.policyRules["routing"] = []okta.PolicyRule{routeRule(1, identifier("IDENTIFIER", "", "SUFFIX", "partner.example"), "SAML2"), routeRule(2, nil, "OKTA")}
	client.identityProviders = []okta.IdentityProvider{defPartner}
	for _, u := range users {
		client.factors[u.ID] = []okta.Factor{defFactor("email")}
	}
	return client
}

// TestMFAValues_LeftOutForAnotherProvidersUsers checks that a user the
// routing rules send to another identity provider leaves the MFA values out
// with an unsupported gap, the counts at the audit level only, and that a
// rule for a domain no user has leaves them in.
func TestMFAValues_LeftOutForAnotherProvidersUsers(t *testing.T) {
	routed := defUser("bo", StatusActive, 1)
	routed.Profile.Login = "bo@partner.example"
	userValues := []string{"/user_security/mfa_coverage_pct", "/user_security/mfa_phishing_resistant_pct", "/policy/mfa_required", "/policy/mfa_required_coverage_pct"}
	userCounts := []string{"/user_security/mfa_user_count", "/user_security/phishing_resistant_user_count", "/policy/mfa_required_user_count"}

	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		_, doc, gaps := defRun(t, routedOrg([]okta.User{defUser("ana", StatusActive, 1), routed}), level)
		want := userValues
		if level == componentsdk.LevelAudit {
			want = append(slices.Clone(userValues), userCounts...)
		}
		for _, pointer := range want {
			section, field := splitPointer(pointer)
			if v, ok := at(doc, section, field); ok {
				t.Errorf("%s %s = %v, want it left out", level, pointer, v)
			}
			if code := gaps[idpPosturePath+"#"+pointer]; code != componentsdk.CodeUnsupported {
				t.Errorf("%s %s gap = %q, want unsupported", level, pointer, code)
			}
		}
	}

	_, doc, _ := defRun(t, routedOrg([]okta.User{defUser("ana", StatusActive, 1)}), componentsdk.LevelAudit)
	wantValues(t, "no one at partner.example", doc, map[[2]string]any{
		{"user_security", "mfa_user_count"}: 1, {"user_security", "mfa_coverage_pct"}: 100, {"policy", "mfa_required"}: true,
	})
}

// TestMFAValues_LeftOutWhenRoutingRulesUnread checks that routing rules that
// can't be read leave the MFA values out with the read's gap, since who
// signs in elsewhere is unknown.
func TestMFAValues_LeftOutWhenRoutingRulesUnread(t *testing.T) {
	client := routedOrg([]okta.User{defUser("ana", StatusActive, 1)})
	client.rulesErr = &okta.APIStatusError{StatusCode: 403, Path: "/api/v1/policies/routing/rules", Code: "E0000006"}
	_, doc, gaps := defRun(t, client, componentsdk.LevelAudit)
	for _, pointer := range []string{"/user_security/mfa_user_count", "/user_security/mfa_coverage_pct", "/privileged_access/privileged_mfa_coverage_pct"} {
		section, field := splitPointer(pointer)
		if v, ok := at(doc, section, field); ok {
			t.Errorf("%s = %v, want it left out", pointer, v)
		}
		if code := gaps[idpPosturePath+"#"+pointer]; code != componentsdk.CodePermissionDenied {
			t.Errorf("%s gap = %q, want permission_denied", pointer, code)
		}
	}
}

func splitPointer(pointer string) (string, string) {
	section, field, _ := strings.Cut(strings.TrimPrefix(pointer, "/"), "/")
	return section, field
}

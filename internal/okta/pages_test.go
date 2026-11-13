package okta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// loopingServer answers every request with body and a next link to the
// second page, so the second page links to itself, as a list that loops
// does. It stops offering the link after 20 requests, so a client that
// follows it still ends.
func loopingServer(t *testing.T, body func(next string) any, link bool) (*httptest.Server, *int) {
	t.Helper()
	requests := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		next := server.URL + r.URL.Path + "?after=cursor&limit=200"
		if requests > 20 {
			next = ""
		}
		if link && next != "" {
			w.Header().Set("Link", "<"+next+`>; rel="next"`)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body(next))
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func TestListsFailOnANextLinkToAPageAlreadyRead(t *testing.T) {
	links := func(next string) map[string]any {
		if next == "" {
			return map[string]any{}
		}
		return map[string]any{"next": map[string]any{"href": next}}
	}
	cases := []struct {
		name string
		body func(next string) any
		link bool
		read func(*Client) error
	}{
		{"users", func(string) any { return []User{{ID: "u1", Status: "ACTIVE"}} }, true, func(c *Client) error {
			return c.FetchUsers(context.Background(), func([]User) error { return nil })
		}},
		{"admin role assignees", func(next string) any {
			return map[string]any{"value": []RoleAssignedUser{{ID: "u1"}}, "_links": links(next)}
		}, false, func(c *Client) error {
			return c.FetchUsersWithRoleAssignments(context.Background(), func([]RoleAssignedUser) error { return nil })
		}},
		{"system log", func(string) any { return []LogEvent{{UUID: "e1", EventType: "user.session.start"}} }, true, func(c *Client) error {
			_, err := c.ListSystemLog(context.Background(), "", time.Time{}, 5000)
			return err
		}},
		{"custom admin roles", func(next string) any {
			return map[string]any{"roles": []IAMRole{{ID: "cr1"}}, "_links": links(next)}
		}, false, func(c *Client) error {
			_, err := c.ListIAMRoles(context.Background())
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, requests := loopingServer(t, tc.body, tc.link)
			client := NewClientWithHTTP(server.Client(), server.URL)
			err := tc.read(client)
			if code := componentsdk.Classify(err); code != componentsdk.CodeInvalidResponse {
				t.Errorf("error = %v (%s), want invalid_response", err, code)
			}
			if *requests != 2 {
				t.Errorf("requests = %d, want 2: the first page, and the second, which links to itself", *requests)
			}
		})
	}
}

func TestFetchPolicies_ActivePolicyMustNameAGroup(t *testing.T) {
	cases := []struct {
		name     string
		policies string
		ok       bool
	}{
		{"active policy for a group", `[{"id":"p1","status":"ACTIVE","priority":1,"conditions":{"people":{"groups":{"include":["g1"]}}}}]`, true},
		{"inactive policy with no conditions", `[{"id":"p1","status":"INACTIVE","priority":1}]`, true},
		{"active policy with no conditions", `[{"id":"p1","status":"ACTIVE","priority":1}]`, false},
		{"active policy with an empty include", `[{"id":"p1","status":"ACTIVE","priority":1,"conditions":{"people":{"groups":{"include":[]}}}}]`, false},
		{"active policy that only excludes", `[{"id":"p1","status":"ACTIVE","priority":1,"conditions":{"people":{"groups":{"exclude":["g1"]}}}}]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.policies))
			}))
			defer server.Close()
			client := NewClientWithHTTP(server.Client(), server.URL)
			_, err := client.FetchPolicies(context.Background(), "OKTA_SIGN_ON")
			if tc.ok && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.ok && componentsdk.Classify(err) != componentsdk.CodeInvalidResponse {
				t.Errorf("error = %v, want invalid_response", err)
			}
		})
	}
}

// answering returns a client whose every request gets body.
func answering(t *testing.T, body string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return NewClientWithHTTP(server.Client(), server.URL)
}

// TestListsRejectWhatOktaNeverSends checks that an answer missing a field
// Okta sends in every item, or a list Okta never leaves empty, fails its
// read. Read as it stands, each would turn what is missing into a value: a
// user with no status into one who isn't enabled, a sign-on rule with no
// requireFactor into one that doesn't require MFA, an empty zone list into
// an org with no zones.
func TestListsRejectWhatOktaNeverSends(t *testing.T) {
	ctx := context.Background()
	users := func(c *Client) error { return c.FetchUsers(ctx, func([]User) error { return nil }) }
	members := func(c *Client) error { return c.FetchGroupUsers(ctx, "g1", func([]User) error { return nil }) }
	assignees := func(c *Client) error {
		return c.FetchUsersWithRoleAssignments(ctx, func([]RoleAssignedUser) error { return nil })
	}
	factors := func(c *Client) error { _, err := c.FetchUserFactors(ctx, "u1"); return err }
	roles := func(c *Client) error { _, err := c.FetchUserRoleAssignments(ctx, "u1"); return err }
	customRoles := func(c *Client) error { _, err := c.ListIAMRoles(ctx); return err }
	permissions := func(c *Client) error { _, err := c.ListRolePermissions(ctx, "cr1"); return err }
	apps := func(c *Client) error { return c.FetchApplications(ctx, func([]Application) error { return nil }) }
	policies := func(policyType string) func(*Client) error {
		return func(c *Client) error { _, err := c.FetchPolicies(ctx, policyType); return err }
	}
	rules := func(policy Policy) func(*Client) error {
		return func(c *Client) error { _, err := c.FetchPolicyRules(ctx, policy); return err }
	}
	authenticators := func(c *Client) error { _, err := c.ListAuthenticators(ctx); return err }
	groups := func(c *Client) error { return c.ListGroups(ctx, func([]Group) error { return nil }) }
	zones := func(c *Client) error { _, err := c.ListNetworkZones(ctx); return err }
	idps := func(c *Client) error { _, err := c.ListIdentityProviders(ctx); return err }
	tokens := func(c *Client) error { _, err := c.ListAPITokens(ctx); return err }
	eventHooks := func(c *Client) error { _, err := c.ListEventHooks(ctx); return err }
	inlineHooks := func(c *Client) error { _, err := c.ListInlineHooks(ctx); return err }
	logs := func(c *Client) error { _, err := c.ListSystemLog(ctx, "", time.Time{}, 5000); return err }

	signOn := Policy{ID: "p1", Type: "OKTA_SIGN_ON"}
	password := Policy{ID: "p2", Type: "PASSWORD"}
	allow := `{"access":"ALLOW","requireFactor":false,"session":{"usePersistentCookie":false,"maxSessionIdleMinutes":120,"maxSessionLifetimeMinutes":0}}`
	signOnRule := func(signon string) string {
		return `[{"id":"r1","status":"ACTIVE","priority":null,"actions":{"signon":` + signon + `}}]`
	}
	without := func(field string) string { return strings.Replace(allow, field, `"x":0`, 1) }
	group := `[{"id":"g1","type":"BUILT_IN","profile":{"name":"Everyone"}}]`
	cases := []struct {
		name string
		body string
		read func(*Client) error
		ok   bool
	}{
		{"users", `[{"id":"u1","status":"ACTIVE","lastLogin":null}]`, users, true},
		{"no users", `[]`, users, false},
		{"a user with no status", `[{"id":"u1"}]`, users, false},
		{"a member with no id", `[{"status":"ACTIVE"}]`, members, false},
		{"a group with no members", `[]`, members, true},
		{"assignees", `{"value":[{"id":"u1"}]}`, assignees, true},
		{"no assignees", `{"value":[]}`, assignees, false},
		{"an assignee with no id", `{"value":[{"orn":"orn:okta:directory:o1:users:u1"}]}`, assignees, false},
		{"no factors", `[]`, factors, true},
		{"a factor with no type", `[{"id":"f1","status":"ACTIVE"}]`, factors, false},
		{"a factor with no status", `[{"id":"f1","factorType":"push"}]`, factors, false},
		{"roles", `[{"id":"ra1","type":"CUSTOM","role":"cr1"}]`, roles, true},
		{"no roles for an assignee", `[]`, roles, false},
		{"a role with no type", `[{"id":"ra1"}]`, roles, false},
		{"a custom role with no role ID", `[{"id":"ra1","type":"CUSTOM"}]`, roles, false},
		{"no custom roles", `{"roles":[]}`, customRoles, true},
		{"a custom role with no id", `{"roles":[{"label":"Help Desk"}]}`, customRoles, false},
		{"no permissions", `{"permissions":[]}`, permissions, true},
		{"no permissions list", `{}`, permissions, false},
		{"apps", `[{"id":"a1","status":"ACTIVE","signOnMode":"SAML_2_0","features":[]}]`, apps, true},
		{"no apps", `[]`, apps, true},
		{"an app with null features", `[{"id":"a1","status":"ACTIVE","signOnMode":"SAML_2_0","features":null}]`, apps, false},
		{"an app with no sign-on mode", `[{"id":"a1","status":"ACTIVE","features":[]}]`, apps, false},
		{"an app with no status", `[{"id":"a1","signOnMode":"SAML_2_0","features":[]}]`, apps, false},
		{"no sign-on policies", `[]`, policies("OKTA_SIGN_ON"), false},
		{"no password policies", `[]`, policies("PASSWORD"), false},
		{"no routing policies", `[]`, policies("IDP_DISCOVERY"), true},
		{"a policy with no priority", `[{"id":"p1","status":"INACTIVE"}]`, policies("OKTA_SIGN_ON"), false},
		{"a policy with no status", `[{"id":"p1","priority":1}]`, policies("OKTA_SIGN_ON"), false},
		{"a sign-on rule", signOnRule(allow), rules(signOn), true},
		{"a denying sign-on rule", signOnRule(`{"access":"DENY"}`), rules(signOn), true},
		{"a sign-on rule with no signon", `[{"id":"r1","status":"ACTIVE"}]`, rules(signOn), false},
		{"a sign-on rule with no requireFactor", signOnRule(without(`"requireFactor":false`)), rules(signOn), false},
		{"a sign-on rule with no idle limit", signOnRule(without(`"maxSessionIdleMinutes":120`)), rules(signOn), false},
		{"a sign-on rule with no lifetime", signOnRule(without(`"maxSessionLifetimeMinutes":0`)), rules(signOn), false},
		{"a sign-on rule with no persistent cookie", signOnRule(without(`"usePersistentCookie":false`)), rules(signOn), false},
		{"a rule with no status", `[{"id":"r1","actions":{"signon":` + allow + `}}]`, rules(signOn), false},
		{"a password rule", `[{"id":"r1","status":"ACTIVE","actions":{"selfServicePasswordReset":{"access":"ALLOW"},"selfServiceUnlock":{"access":"DENY"}}}]`, rules(password), true},
		{"a password rule with no unlock", `[{"id":"r1","status":"ACTIVE","actions":{"selfServicePasswordReset":{"access":"ALLOW"}}}]`, rules(password), false},
		{"a policy with no rules", `[]`, rules(signOn), true},
		{"a default policy with no rules", `[]`, rules(Policy{ID: "p1", Type: "OKTA_SIGN_ON", System: true}), false},
		{"no authenticators", `[]`, authenticators, false},
		{"an authenticator with no key", `[{"id":"aut1","status":"ACTIVE"}]`, authenticators, false},
		{"groups", group, groups, true},
		{"a group with no type", strings.Replace(group, `"type":"BUILT_IN",`, "", 1), groups, false},
		{"zones", `[{"id":"z1","type":"IP","gateways":null}]`, zones, true},
		{"no zones", `[]`, zones, false},
		{"a zone with no type", `[{"id":"z1","gateways":null}]`, zones, false},
		{"no identity providers", `[]`, idps, true},
		{"a provider with no provisioning action", `[{"id":"i1","type":"SAML2","policy":{"provisioning":{}}}]`, idps, false},
		{"no tokens for an API token", `[]`, tokens, false},
		{"a token with no lastUpdated", `[{"id":"t1","name":"ci"}]`, tokens, false},
		{"an event hook with no status", `[{"id":"h1","name":"Notify"}]`, eventHooks, false},
		{"an inline hook with no status", `[{"id":"h1","name":"Transform"}]`, inlineHooks, false},
		{"no events", `[]`, logs, true},
		{"an event with no type", `[{"uuid":"e1"}]`, logs, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.read(answering(t, tc.body))
			switch {
			case tc.ok && err != nil:
				t.Errorf("unexpected error: %v", err)
			case !tc.ok && componentsdk.Classify(err) != componentsdk.CodeInvalidResponse:
				t.Errorf("error = %v, want invalid_response", err)
			}
		})
	}
}

// TestNoTokensForAServiceApp checks that a service app reads an empty token
// list as an org with no API tokens. It signs in with no token of its own.
func TestNoTokensForAServiceApp(t *testing.T) {
	client := answering(t, `[]`)
	client.oauth = &oauthCredentials{}
	if tokens, err := client.ListAPITokens(context.Background()); err != nil || len(tokens) != 0 {
		t.Errorf("tokens = %v, err = %v, want none", tokens, err)
	}
}

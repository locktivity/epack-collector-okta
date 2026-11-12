package okta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		{"users", func(string) any { return []User{{ID: "u1"}} }, true, func(c *Client) error {
			return c.FetchUsers(context.Background(), func([]User) error { return nil })
		}},
		{"admin role assignees", func(next string) any {
			return map[string]any{"value": []RoleAssignedUser{{ID: "u1"}}, "_links": links(next)}
		}, false, func(c *Client) error {
			return c.FetchUsersWithRoleAssignments(context.Background(), func([]RoleAssignedUser) error { return nil })
		}},
		{"system log", func(string) any { return []LogEvent{{UUID: "e1"}} }, true, func(c *Client) error {
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
		{"active policy for a group", `[{"id":"p1","status":"ACTIVE","conditions":{"people":{"groups":{"include":["g1"]}}}}]`, true},
		{"inactive policy with no conditions", `[{"id":"p1","status":"INACTIVE"}]`, true},
		{"active policy with no conditions", `[{"id":"p1","status":"ACTIVE"}]`, false},
		{"active policy with an empty include", `[{"id":"p1","status":"ACTIVE","conditions":{"people":{"groups":{"include":[]}}}}]`, false},
		{"active policy that only excludes", `[{"id":"p1","status":"ACTIVE","conditions":{"people":{"groups":{"exclude":["g1"]}}}}]`, false},
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

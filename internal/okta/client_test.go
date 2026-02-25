package okta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchUsers(t *testing.T) {
	users := []User{
		{ID: "user1", Status: "ACTIVE", LastLogin: time.Now()},
		{ID: "user2", Status: "ACTIVE", LastLogin: time.Now()},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(users)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	var fetched []User
	err := client.FetchUsers(context.Background(), func(u []User) error {
		fetched = append(fetched, u...)
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fetched) != 2 {
		t.Errorf("expected 2 users, got %d", len(fetched))
	}
}

func TestFetchUsers_Pagination(t *testing.T) {
	page := 0
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if page == 0 {
			// First page - include Link header for next page
			w.Header().Set("Link", `<`+serverURL+`/api/v1/users?after=cursor123>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]User{{ID: "user1"}})
			page++
		} else {
			// Second page - no Link header
			_ = json.NewEncoder(w).Encode([]User{{ID: "user2"}})
		}
	}))
	defer server.Close()
	serverURL = server.URL

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	var fetched []User
	err := client.FetchUsers(context.Background(), func(u []User) error {
		fetched = append(fetched, u...)
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fetched) != 2 {
		t.Errorf("expected 2 users across pages, got %d", len(fetched))
	}
}

func TestFetchUsers_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	err := client.FetchUsers(context.Background(), func(u []User) error {
		return nil
	})

	if err == nil {
		t.Error("expected error for 403 response")
	}
}

func TestFetchUserFactors(t *testing.T) {
	factors := []Factor{
		{ID: "f1", FactorType: "push", Status: "ACTIVE"},
		{ID: "f2", FactorType: "webauthn", Status: "ACTIVE"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/user123/factors" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(factors)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	fetched, err := client.FetchUserFactors(context.Background(), "user123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fetched) != 2 {
		t.Errorf("expected 2 factors, got %d", len(fetched))
	}

	if fetched[1].FactorType != "webauthn" {
		t.Errorf("expected webauthn factor, got %s", fetched[1].FactorType)
	}
}

func TestFetchUserFactors_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	// 404 means user has no factors - should return empty slice, no error
	factors, err := client.FetchUserFactors(context.Background(), "user123")
	if err != nil {
		t.Errorf("expected no error for 404, got %v", err)
	}
	if factors == nil {
		t.Errorf("expected empty slice for 404, got nil")
	}
	if len(factors) != 0 {
		t.Errorf("expected empty slice for 404, got %d factors", len(factors))
	}
}

func TestFetchUserFactors_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	// 403 means permission error - should return error
	_, err := client.FetchUserFactors(context.Background(), "user123")
	if err == nil {
		t.Error("expected error for 403 response")
	}
}

func TestFetchApplications(t *testing.T) {
	apps := []Application{
		{ID: "app1", SignOnMode: "SAML_2_0", Status: "ACTIVE"},
		{ID: "app2", SignOnMode: "OPENID_CONNECT", Status: "ACTIVE"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/apps" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(apps)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	var fetched []Application
	err := client.FetchApplications(context.Background(), func(a []Application) error {
		fetched = append(fetched, a...)
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fetched) != 2 {
		t.Errorf("expected 2 apps, got %d", len(fetched))
	}
}

func TestFetchPolicies(t *testing.T) {
	policies := []Policy{
		{ID: "policy1", Status: "ACTIVE", Type: "OKTA_SIGN_ON"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/policies" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("type") != "OKTA_SIGN_ON" {
			t.Errorf("expected type=OKTA_SIGN_ON, got %s", r.URL.Query().Get("type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(policies)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	fetched, err := client.FetchPolicies(context.Background(), "OKTA_SIGN_ON")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fetched) != 1 {
		t.Errorf("expected 1 policy, got %d", len(fetched))
	}
}

func TestFetchPolicyRules(t *testing.T) {
	rules := []PolicyRule{
		{ID: "rule1", Status: "ACTIVE"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/policies/policy123/rules" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rules)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	fetched, err := client.FetchPolicyRules(context.Background(), "policy123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fetched) != 1 {
		t.Errorf("expected 1 rule, got %d", len(fetched))
	}
}

func TestFetchOrgSettings(t *testing.T) {
	settings := OrgSettings{
		ID:          "org123",
		Subdomain:   "company",
		CompanyName: "Company Inc",
		Status:      "ACTIVE",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/org" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(settings)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	fetched, err := client.FetchOrgSettings(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fetched.CompanyName != "Company Inc" {
		t.Errorf("expected Company Inc, got %s", fetched.CompanyName)
	}
}

func TestGetNextLink(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "empty header",
			header:   "",
			expected: "",
		},
		{
			name:     "no next link",
			header:   `<https://example.okta.com/api/v1/users>; rel="self"`,
			expected: "",
		},
		{
			name:     "has next link",
			header:   `<https://example.okta.com/api/v1/users?after=abc123>; rel="next"`,
			expected: "/api/v1/users?after=abc123",
		},
		{
			name:     "multiple links",
			header:   `<https://example.okta.com/api/v1/users>; rel="self", <https://example.okta.com/api/v1/users?after=xyz>; rel="next"`,
			expected: "/api/v1/users?after=xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getNextLink(tt.header)
			if result != tt.expected {
				t.Errorf("getNextLink(%q) = %q, want %q", tt.header, result, tt.expected)
			}
		})
	}
}

func TestBuildBaseURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"company.okta.com", "https://company.okta.com"},
		{"https://company.okta.com", "https://company.okta.com"},
		{"http://company.okta.com", "https://company.okta.com"},
		{"company.okta.com/", "https://company.okta.com"},
	}

	for _, tt := range tests {
		result := buildBaseURL(tt.input)
		if result != tt.expected {
			t.Errorf("buildBaseURL(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestAuthorizationHeader(t *testing.T) {
	var capturedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]User{})
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("my-test-token")

	_ = client.FetchUsers(context.Background(), func(u []User) error { return nil })

	if capturedAuth != "SSWS my-test-token" {
		t.Errorf("expected 'SSWS my-test-token', got %q", capturedAuth)
	}
}

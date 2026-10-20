package okta

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
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

	// A user with no factors gets an empty list. A 404 means the user is
	// gone, so it is an error, never "no factors enrolled".
	factors, err := client.FetchUserFactors(context.Background(), "user123")
	if err == nil {
		t.Fatalf("expected an error for 404, got %d factors", len(factors))
	}
	if code := componentsdk.Classify(err); code != componentsdk.CodeInvalidResponse {
		t.Errorf("Classify(404) = %s, want invalid_response", code)
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

func TestFetchGroupUsers_Pagination(t *testing.T) {
	page := 0
	var serverURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/groups/group123/users" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")

		if page == 0 {
			w.Header().Set("Link", `<`+serverURL+`/api/v1/groups/group123/users?after=cursor123>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]User{{ID: "user1"}})
			page++
			return
		}

		_ = json.NewEncoder(w).Encode([]User{{ID: "user2"}})
	}))
	defer server.Close()
	serverURL = server.URL

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	var fetched []User
	err := client.FetchGroupUsers(context.Background(), "group123", func(users []User) error {
		fetched = append(fetched, users...)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fetched) != 2 {
		t.Fatalf("expected 2 group users, got %d", len(fetched))
	}
}

func TestFetchUsersWithRoleAssignments(t *testing.T) {
	page := 0
	var serverURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/iam/assignees/users" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")

		if page == 0 {
			_ = json.NewEncoder(w).Encode(RoleAssignedUsersResponse{
				Value: &[]RoleAssignedUser{{ID: "user1"}},
				Links: struct {
					Next *struct {
						Href string `json:"href"`
					} `json:"next,omitempty"`
				}{
					Next: &struct {
						Href string `json:"href"`
					}{Href: serverURL + "/api/v1/iam/assignees/users?after=abc123"},
				},
			})
			page++
			return
		}

		_ = json.NewEncoder(w).Encode(RoleAssignedUsersResponse{
			Value: &[]RoleAssignedUser{{ID: "user2"}},
		})
	}))
	defer server.Close()
	serverURL = server.URL

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	var fetched []RoleAssignedUser
	err := client.FetchUsersWithRoleAssignments(context.Background(), func(users []RoleAssignedUser) error {
		fetched = append(fetched, users...)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fetched) != 2 {
		t.Fatalf("expected 2 role-assigned users, got %d", len(fetched))
	}
}

func TestFetchUserRoleAssignments(t *testing.T) {
	roles := []RoleAssignment{
		{ID: "r1", Type: "USER_ADMIN", AssignmentType: "USER"},
		{ID: "r2", Type: "SUPER_ADMIN", AssignmentType: "GROUP"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/user123/roles" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(roles)
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")

	fetched, err := client.FetchUserRoleAssignments(context.Background(), "user123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fetched) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(fetched))
	}
	if fetched[1].Type != "SUPER_ADMIN" {
		t.Fatalf("expected SUPER_ADMIN, got %s", fetched[1].Type)
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

func TestGetPathAndQuery(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		expected string
	}{
		{name: "empty", rawURL: "", expected: ""},
		{name: "path only", rawURL: "https://example.okta.com/api/v1/users", expected: "/api/v1/users"},
		{name: "path and query", rawURL: "https://example.okta.com/api/v1/iam/assignees/users?after=abc123&limit=100", expected: "/api/v1/iam/assignees/users?after=abc123&limit=100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getPathAndQuery(tt.rawURL); got != tt.expected {
				t.Fatalf("getPathAndQuery(%q) = %q, want %q", tt.rawURL, got, tt.expected)
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

// runOkta runs handler in process against responses at the audit level, so
// the result keeps its request rows, and fails the test on a request no
// response answers.
func runOkta(t *testing.T, responses []collectortest.Response, handler componentsdk.CollectorHandler) componentsdk.InProcessResult {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(componentsdk.CollectorSpec{Name: "okta"}, handler, componentsdk.InProcessOptions{
		Config:    map[string]any{"level": "audit"},
		Transport: replay,
		Seed:      1,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		Clock:     func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
	for _, request := range replay.Unmatched() {
		t.Errorf("no canned response for %s", request)
	}
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	return res
}

// sdkClient builds the HTTP client Run builds, with Okta's vendor code hook.
func sdkClient(ctx componentsdk.CollectorContext) *http.Client {
	return componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{CredentialHosts: []string{"acme.okta.com"}, VendorCode: VendorCode})
}

func emitNothing(ctx componentsdk.CollectorContext) error {
	return ctx.Emit([]componentsdk.CollectedArtifact{componentsdk.JSONArtifact("artifacts/okta.json", map[string]any{}, componentsdk.ArtifactMeta{})})
}

func TestErrorsFromAResponseNameItsCall(t *testing.T) {
	const base = "https://acme.okta.com"
	res := runOkta(t, []collectortest.Response{
		{URL: base + "/api/v1/users/me", Body: `{"id":"00u1"}`},
		{URL: base + "/api/v1/users?limit=200", Body: `null`},
		{URL: base + "/api/v1/users/00u1/factors", Status: http.StatusForbidden,
			Body: `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}`},
		{URL: base + "/api/v1/org", Body: `{"id":`},
	}, func(ctx componentsdk.CollectorContext) error {
		client := NewClient(sdkClient(ctx), "acme.okta.com", "test-token")
		if _, err := client.SignIn(ctx.Context()); err != nil {
			return err
		}
		rec := componentsdk.Records(ctx)
		at := func(pointer string) componentsdk.Location {
			return componentsdk.Location{Path: "artifacts/okta.json", Pointer: pointer}
		}
		rec.NotCollected(at("/users"), client.FetchUsers(ctx.Context(), func([]User) error { return nil }))
		_, err := client.FetchUserFactors(ctx.Context(), "00u1")
		rec.NotCollected(at("/factors"), err)
		_, err = client.FetchOrgSettings(ctx.Context())
		rec.NotCollected(at("/org"), err)
		return emitNothing(ctx)
	})

	// A list that is not there, a refusal, and a body cut short.
	want := map[string]componentsdk.Gap{
		"/users":   {Operation: "okta.users.list", Call: 2, Code: componentsdk.CodeInvalidResponse},
		"/factors": {Operation: "okta.users.factors.list", Call: 3, Code: componentsdk.CodePermissionDenied, VendorCode: "E0000006"},
		"/org":     {Operation: "okta.org.get", Call: 4, Code: componentsdk.CodeInvalidResponse},
	}
	if len(res.Result.Gaps) != len(want) {
		t.Fatalf("gaps = %+v, want %d", res.Result.Gaps, len(want))
	}
	for _, g := range res.Result.Gaps {
		w := want[g.Pointer]
		if g.Operation != w.Operation || g.Call != w.Call || g.Code != w.Code || g.VendorCode != w.VendorCode {
			t.Errorf("gap at %s = %+v, want %s call %d with code %s and vendor code %q", g.Pointer, g, w.Operation, w.Call, w.Code, w.VendorCode)
		}
	}
	for _, row := range res.Result.Calls.Requests {
		if want := map[int]string{3: "E0000006"}[row.Call]; row.VendorCode != want {
			t.Errorf("call %d (%s) has vendor code %q, want %q", row.Call, row.Operation, row.VendorCode, want)
		}
	}
}

func TestTokenEndpointErrorsNameTheirCall(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	res := runOkta(t, []collectortest.Response{{
		Method: http.MethodPost, URL: "https://acme.okta.com/oauth2/v1/token", Status: http.StatusUnauthorized,
		Body: `{"error":"invalid_client","error_description":"The client_assertion signature is invalid."}`,
	}}, func(ctx componentsdk.CollectorContext) error {
		client, err := NewClientWithOAuth(sdkClient(ctx), "acme.okta.com", "0oa-app", "key-1", keyPEM, []string{"okta.users.read"}, time.Now)
		if err != nil {
			return err
		}
		_, err = client.SignIn(ctx.Context())
		componentsdk.Records(ctx).NotCollected(componentsdk.Location{Path: "artifacts/okta.json", Pointer: "/token"}, err)
		return emitNothing(ctx)
	})
	if g := res.Result.Gaps[0]; g.Operation != "okta.token.create" || g.Call != 1 || g.Code != componentsdk.CodeAuthFailed || g.VendorCode != "invalid_client" {
		t.Errorf("gap = %+v, want the token call with auth_failed and invalid_client", g)
	}
	if rows := res.Result.Calls.Requests; len(rows) != 1 || rows[0].VendorCode != "invalid_client" {
		t.Errorf("rows = %+v, want the token call's row with invalid_client", rows)
	}
}

func TestVendorCode(t *testing.T) {
	for body, want := range map[string]string{
		`{"errorCode":"E0000047","errorSummary":"API call exceeded rate limit due to too many requests."}`: "E0000047",
		`{"error":"invalid_client","error_description":"The client secret supplied is invalid."}`:          "invalid_client",
		`{"errorCode":"E0000006","error":"access_denied"}`:                                                 "E0000006",
		`<html>Service Unavailable</html>`:                                                                 "",
		`{}`:                                                                                               "",
	} {
		if got := VendorCode(nil, []byte(body)); got != want {
			t.Errorf("VendorCode(%s) = %q, want %q", body, got, want)
		}
	}
}

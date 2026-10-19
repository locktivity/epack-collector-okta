package okta

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/locktivity/epack/componentsdk"
)

func TestSignInWithAPIToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/me" || r.Header.Get("Authorization") != "SSWS test-token" {
			t.Errorf("unexpected request %s with %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"id":"00u1","profile":{"login":"admin@acme.com"}}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	client.SetToken("test-token")
	identity, err := client.SignIn(context.Background())
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if identity.Kind != "api_token" || identity.ID != "00u1" {
		t.Errorf("identity = %+v", identity)
	}
}

func TestSignInRejectsAnInvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, err := client.SignIn(context.Background())
	if code := componentsdk.Classify(err); code != componentsdk.CodeAuthFailed {
		t.Errorf("Classify = %s, want auth_failed (%v)", code, err)
	}
	if vendor := componentsdk.VendorCodeOf(err); vendor != "E0000011" {
		t.Errorf("VendorCodeOf = %q, want E0000011", vendor)
	}
}

func TestSignInWithOAuthExchangesASignedAssertion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	var tokenURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/v1/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if got := r.PostForm.Get("scope"); got != "okta.users.read okta.apps.read" {
				t.Errorf("scope = %q", got)
			}
			claims := jwt.MapClaims{}
			token, _, err := jwt.NewParser().ParseUnverified(r.PostForm.Get("client_assertion"), claims)
			if err != nil {
				t.Fatalf("client_assertion: %v", err)
			}
			if token.Header["kid"] != "key-1" || claims["aud"] != tokenURL || claims["iat"] != float64(now.Unix()) {
				t.Errorf("assertion header %v claims %v", token.Header, claims)
			}
			_, _ = w.Write([]byte(`{"token_type":"Bearer","access_token":"access-123","scope":"okta.users.read okta.apps.read"}`))
		case "/api/v1/authenticators":
			if r.Header.Get("Authorization") != "Bearer access-123" {
				t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer server.Close()
	orgDomain := strings.TrimPrefix(server.URL, "https://")
	tokenURL = server.URL + "/oauth2/v1/token"

	client, err := NewClientWithOAuth(server.Client(), orgDomain, "0oa-app", "key-1", keyPEM, []string{"okta.users.read", "okta.apps.read"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	identity, err := client.SignIn(context.Background())
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if identity.Kind != "service_app" || identity.ID != "0oa-app" || len(identity.Scopes) != 2 {
		t.Errorf("identity = %+v", identity)
	}
	if _, err := client.ListAuthenticators(context.Background()); err != nil {
		t.Errorf("a call after sign-in failed: %v", err)
	}
}

func TestNewClientWithOAuthRejectsAMalformedKey(t *testing.T) {
	_, err := NewClientWithOAuth(http.DefaultClient, "acme.okta.com", "0oa-app", "key-1", []byte("not a key"), nil, time.Now)
	if code := componentsdk.Classify(err); code != componentsdk.CodeConfigInvalid {
		t.Errorf("Classify = %s, want config_invalid (%v)", code, err)
	}
}

func TestTokenErrorCodes(t *testing.T) {
	cases := []struct {
		status    int
		oauthCode string
		want      componentsdk.Code
	}{
		{http.StatusUnauthorized, "invalid_client", componentsdk.CodeAuthFailed},
		{http.StatusBadRequest, "invalid_client", componentsdk.CodeAuthFailed},
		{http.StatusBadRequest, "invalid_dpop_proof", componentsdk.CodeAuthFailed},
		{http.StatusBadRequest, "invalid_scope", componentsdk.CodePermissionDenied},
		{http.StatusBadRequest, "use_dpop_nonce", componentsdk.CodeInvalidResponse},
		{http.StatusServiceUnavailable, "invalid_request", componentsdk.CodeVendorError},
	}
	for _, tc := range cases {
		err := &TokenError{StatusCode: tc.status, OAuthCode: tc.oauthCode}
		if got := componentsdk.Classify(err); got != tc.want {
			t.Errorf("%d %s: Classify = %s, want %s", tc.status, tc.oauthCode, got, tc.want)
		}
	}
}

func TestAResponseWithoutItsListIsInvalid(t *testing.T) {
	for _, body := range []string{`{}`, `null`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		client := NewClientWithHTTP(server.Client(), server.URL)
		err := client.FetchUsers(context.Background(), func([]User) error { return nil })
		if code := componentsdk.Classify(err); code != componentsdk.CodeInvalidResponse {
			t.Errorf("body %s: Classify = %s, want invalid_response (%v)", body, code, err)
		}
		server.Close()
	}
}

func TestFeatureNotEnabledIsNotLicensed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorCode":"E0000015","errorSummary":"You do not have permission to access the feature you are requesting"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, err := client.FetchDeviceAssurancePolicies(context.Background())
	if code := componentsdk.Classify(err); code != componentsdk.CodeNotLicensed {
		t.Errorf("Classify = %s, want not_licensed (%v)", code, err)
	}
}

func TestOrgPreferencesWithoutSelfServiceUnlockIsInvalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"showEndUserFooter":true}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	_, err := client.FetchOrgPreferences(context.Background())
	if code := componentsdk.Classify(err); code != componentsdk.CodeInvalidResponse {
		t.Errorf("Classify = %s, want invalid_response (%v)", code, err)
	}
}

func TestOrgContactsReturnUserIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"userId":"00u-` + strings.TrimPrefix(r.URL.Path, "/api/v1/org/contacts/") + `"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP(server.Client(), server.URL)
	contacts, err := client.FetchOrgContactUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 2 || contacts[0] != (OrgContact{Type: "BILLING", UserID: "00u-BILLING"}) || contacts[1].UserID != "00u-TECHNICAL" {
		t.Errorf("contacts = %+v", contacts)
	}
}

func TestHost(t *testing.T) {
	for input, want := range map[string]string{
		"company.okta.com":          "company.okta.com",
		"https://Company.okta.com/": "company.okta.com",
		"":                          "",
	} {
		if got := Host(input); got != want {
			t.Errorf("Host(%q) = %q, want %q", input, got, want)
		}
	}
}

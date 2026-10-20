package okta

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/locktivity/epack/componentsdk"
)

// oauthCredentials sign the client assertion a service app exchanges for an
// access token.
type oauthCredentials struct {
	clientID string
	keyID    string
	key      *rsa.PrivateKey
	scopes   []string
	now      func() time.Time
}

// NewClientWithOAuth creates a client using OAuth 2.0 private key JWT.
// This is the recommended authentication method.
// keyID is the key identifier from Okta (found in the public keys section of your app).
// scopes is the set of OAuth scopes to request; scopes the service app has not
// been granted are dropped from the issued token. The key is parsed now; the
// token exchange happens at SignIn, with assertion times read from now.
func NewClientWithOAuth(httpClient *http.Client, orgDomain, clientID, keyID string, privateKey []byte, scopes []string, now func() time.Time) (*Client, error) {
	key, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, componentsdk.CodeError(componentsdk.CodeConfigInvalid,
			fmt.Errorf("OKTA_PRIVATE_KEY is not a PEM-encoded RSA private key: %w", err))
	}

	return &Client{
		httpClient: httpClient,
		baseURL:    buildBaseURL(orgDomain),
		authType:   "Bearer",
		oauth: &oauthCredentials{
			clientID: clientID,
			keyID:    keyID,
			key:      key,
			scopes:   scopes,
			now:      now,
		},
	}, nil
}

// parsePrivateKey parses a PEM-encoded RSA private key.
func parsePrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS#8 first (more common for OAuth)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS#1
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// generateClientAssertionJWT creates a JWT for OAuth 2.0 client credentials flow.
// keyID is the key identifier from Okta that must match the public key registered in your app.
func generateClientAssertionJWT(clientID, tokenURL, keyID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"aud": tokenURL,
		"iss": clientID,
		"sub": clientID,
		"iat": now.Unix(),
		"exp": now.Add(jwtExpiry).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Set the key ID in the JWT header - required by Okta to identify which public key to use
	token.Header["kid"] = keyID
	return token.SignedString(key)
}

// exchangeToken exchanges a client assertion JWT for an access token,
// requesting the client's scopes.
func (c *Client) exchangeToken(ctx context.Context) (*Identity, error) {
	const op = "okta.token.create"
	tokenURL := c.baseURL + "/oauth2/v1/token"

	assertion, err := generateClientAssertionJWT(c.oauth.clientID, tokenURL, c.oauth.keyID, c.oauth.key, c.oauth.now())
	if err != nil {
		return nil, fmt.Errorf("signing the client assertion: %w", err)
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", strings.Join(c.oauth.scopes, " "))
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", assertion)

	// The exchange only mints a token, so a retry is harmless.
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op, Safe: true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("reading the token response: %w", err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, componentsdk.ResponseError(resp, newTokenError(resp, body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("decoding the token response: %w", err))
	}
	if result.AccessToken == "" {
		return nil, invalidResponse(resp, op, "has no access_token")
	}

	c.accessToken = result.AccessToken
	return &Identity{
		Kind:            "service_app",
		AuthMethod:      componentsdk.AuthPrivateKeyJWT,
		ID:              c.oauth.clientID,
		RequestedScopes: append([]string(nil), c.oauth.scopes...),
		Scopes:          strings.Fields(result.Scope),
	}, nil
}

// TokenError is an error response from the org's token endpoint.
type TokenError struct {
	StatusCode int
	Header     http.Header
	// OAuthCode is the OAuth error, such as invalid_client.
	OAuthCode   string
	Description string
}

func newTokenError(resp *http.Response, body []byte) *TokenError {
	e := &TokenError{StatusCode: resp.StatusCode, Header: resp.Header}
	var payload struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &payload) == nil {
		e.OAuthCode = payload.Error
		e.Description = payload.ErrorDescription
	}
	return e
}

func (e *TokenError) Error() string {
	if e.OAuthCode != "" {
		return fmt.Sprintf("token exchange failed with status %d: %s - %s", e.StatusCode, e.OAuthCode, e.Description)
	}
	return fmt.Sprintf("token exchange failed with status %d", e.StatusCode)
}

func (e *TokenError) HTTPStatus() int         { return e.StatusCode }
func (e *TokenError) HTTPHeader() http.Header { return e.Header }
func (e *TokenError) VendorCode() string      { return e.OAuthCode }

// CollectionCode reads the OAuth error of a 400, which Okta sends both for
// credentials it rejects and for scopes the service app was not granted.
func (e *TokenError) CollectionCode() componentsdk.Code {
	if e.StatusCode != http.StatusBadRequest {
		return ""
	}
	code, _ := componentsdk.OAuthErrorCode(e.OAuthCode)
	return code
}

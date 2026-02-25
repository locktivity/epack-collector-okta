package okta

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OktaClient defines the interface for Okta API operations.
// This interface allows for easy mocking in tests.
type OktaClient interface {
	// User operations
	FetchUsers(ctx context.Context, callback func([]User) error) error
	FetchUserFactors(ctx context.Context, userID string) ([]Factor, error)

	// Application operations
	FetchApplications(ctx context.Context, callback func([]Application) error) error

	// Policy operations
	FetchPolicies(ctx context.Context, policyType string) ([]Policy, error)
	FetchPolicyRules(ctx context.Context, policyID string) ([]PolicyRule, error)

	// Org settings
	FetchOrgSettings(ctx context.Context) (*OrgSettings, error)
}

// Client wraps the Okta REST API client.
type Client struct {
	httpClient  *http.Client
	baseURL     string
	accessToken string // OAuth 2.0 access token or SSWS token
	authType    string // "Bearer" or "SSWS"
}

// Ensure Client implements OktaClient.
var _ OktaClient = (*Client)(nil)

// NewClient creates a new Okta client with API token (SSWS) authentication.
func NewClient(orgDomain, apiToken string) *Client {
	return &Client{
		httpClient:  &http.Client{Timeout: HTTPTimeout},
		baseURL:     buildBaseURL(orgDomain),
		accessToken: apiToken,
		authType:    "SSWS",
	}
}

// NewClientWithOAuth creates a client using OAuth 2.0 private key JWT.
// This is the recommended authentication method.
func NewClientWithOAuth(orgDomain, clientID string, privateKey []byte) (*Client, error) {
	baseURL := buildBaseURL(orgDomain)

	// Parse the private key
	key, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Generate JWT for client credentials grant
	token, err := generateClientAssertionJWT(clientID, baseURL, key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Exchange JWT for access token
	accessToken, err := exchangeJWTForToken(baseURL, clientID, token)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange JWT for token: %w", err)
	}

	return &Client{
		httpClient:  &http.Client{Timeout: HTTPTimeout},
		baseURL:     baseURL,
		accessToken: accessToken,
		authType:    "Bearer",
	}, nil
}

// NewClientWithHTTP creates a client with a custom HTTP client and base URL (for testing).
func NewClientWithHTTP(httpClient *http.Client, baseURL string) *Client {
	return &Client{
		httpClient: httpClient,
		baseURL:    baseURL,
		authType:   "SSWS",
	}
}

// SetToken sets the access token for testing purposes.
func (c *Client) SetToken(token string) {
	c.accessToken = token
}

// buildBaseURL constructs the Okta API base URL from the org domain.
func buildBaseURL(orgDomain string) string {
	// Remove any protocol prefix if present
	orgDomain = strings.TrimPrefix(orgDomain, "https://")
	orgDomain = strings.TrimPrefix(orgDomain, "http://")
	// Remove trailing slash
	orgDomain = strings.TrimSuffix(orgDomain, "/")
	return fmt.Sprintf("https://%s", orgDomain)
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
func generateClientAssertionJWT(clientID, baseURL string, key *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"aud": fmt.Sprintf("%s/oauth2/v1/token", baseURL),
		"iss": clientID,
		"sub": clientID,
		"iat": now.Unix(),
		"exp": now.Add(jwtExpiry).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}

// exchangeJWTForToken exchanges a client assertion JWT for an access token.
func exchangeJWTForToken(baseURL, clientID, assertion string) (string, error) {
	tokenURL := fmt.Sprintf("%s/oauth2/v1/token", baseURL)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "okta.users.read okta.apps.read okta.policies.read")
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", assertion)

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Read error response for debugging
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error != "" {
			return "", fmt.Errorf("token exchange failed: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return "", fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.AccessToken == "" {
		return "", fmt.Errorf("token exchange returned empty access token")
	}

	return result.AccessToken, nil
}


// doRequest performs an HTTP request with authentication and rate limit handling.
func (c *Client) doRequest(ctx context.Context, method, path string) (*http.Response, error) {
	reqURL := fmt.Sprintf("%s%s", c.baseURL, path)

	for attempt := 0; attempt <= maxRateLimitRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("%s %s", c.authType, c.accessToken))

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		// Handle rate limiting
		if resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()

			// Don't retry if we've exhausted attempts
			if attempt >= maxRateLimitRetries {
				return nil, fmt.Errorf("rate limited after %d retries", maxRateLimitRetries)
			}

			waitDuration := defaultBackoff
			resetHeader := resp.Header.Get("X-Rate-Limit-Reset")
			if resetHeader != "" {
				if resetTime, err := strconv.ParseInt(resetHeader, 10, 64); err == nil {
					waitDuration = time.Until(time.Unix(resetTime, 0)) + time.Second
				}
			}

			// Cap wait duration
			if waitDuration > maxRateLimitWait {
				return nil, fmt.Errorf("rate limit reset too far in future: %v", waitDuration)
			}
			if waitDuration < 0 {
				waitDuration = defaultBackoff
			}

			// Wait with context cancellation support
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitDuration):
				continue
			}
		}

		return resp, nil
	}

	return nil, fmt.Errorf("rate limited")
}

// FetchUsers fetches all users with pagination.
func (c *Client) FetchUsers(ctx context.Context, callback func([]User) error) error {
	path := fmt.Sprintf("/api/v1/users?limit=%d", paginationLimit)

	for path != "" {
		resp, err := c.doRequest(ctx, "GET", path)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return fmt.Errorf("users API returned status %d", resp.StatusCode)
		}

		var users []User
		if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
			_ = resp.Body.Close()
			return err
		}
		_ = resp.Body.Close()

		if err := callback(users); err != nil {
			return err
		}

		// Check for next page
		path = getNextLink(resp.Header.Get("Link"))
	}

	return nil
}

// FetchUserFactors fetches all MFA factors for a user.
// Returns empty slice if user has no factors, error if request fails.
func (c *Client) FetchUserFactors(ctx context.Context, userID string) ([]Factor, error) {
	path := fmt.Sprintf("/api/v1/users/%s/factors", userID)

	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// User has no factors enrolled - this is valid, return empty slice
		return []Factor{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("factors API returned status %d for user %s", resp.StatusCode, userID)
	}

	var factors []Factor
	if err := json.NewDecoder(resp.Body).Decode(&factors); err != nil {
		return nil, err
	}

	return factors, nil
}

// FetchApplications fetches all applications with pagination.
func (c *Client) FetchApplications(ctx context.Context, callback func([]Application) error) error {
	path := fmt.Sprintf("/api/v1/apps?limit=%d", paginationLimit)

	for path != "" {
		resp, err := c.doRequest(ctx, "GET", path)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			// Read error response for debugging
			var errResp struct {
				ErrorCode    string `json:"errorCode"`
				ErrorSummary string `json:"errorSummary"`
				ErrorLink    string `json:"errorLink"`
				ErrorId      string `json:"errorId"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			_ = resp.Body.Close()
			if errResp.ErrorCode != "" {
				return fmt.Errorf("apps API returned status %d: %s - %s", resp.StatusCode, errResp.ErrorCode, errResp.ErrorSummary)
			}
			return fmt.Errorf("apps API returned status %d", resp.StatusCode)
		}

		var apps []Application
		if err := json.NewDecoder(resp.Body).Decode(&apps); err != nil {
			_ = resp.Body.Close()
			return err
		}
		_ = resp.Body.Close()

		if err := callback(apps); err != nil {
			return err
		}

		// Check for next page
		path = getNextLink(resp.Header.Get("Link"))
	}

	return nil
}

// FetchPolicies fetches all policies of a given type.
func (c *Client) FetchPolicies(ctx context.Context, policyType string) ([]Policy, error) {
	path := fmt.Sprintf("/api/v1/policies?type=%s", policyType)

	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policies API returned status %d", resp.StatusCode)
	}

	var policies []Policy
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return nil, err
	}

	return policies, nil
}

// FetchPolicyRules fetches all rules for a policy.
func (c *Client) FetchPolicyRules(ctx context.Context, policyID string) ([]PolicyRule, error) {
	path := fmt.Sprintf("/api/v1/policies/%s/rules", policyID)

	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy rules API returned status %d", resp.StatusCode)
	}

	var rules []PolicyRule
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		return nil, err
	}

	return rules, nil
}

// FetchOrgSettings fetches organization settings.
func (c *Client) FetchOrgSettings(ctx context.Context) (*OrgSettings, error) {
	path := "/api/v1/org"

	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("org API returned status %d", resp.StatusCode)
	}

	var settings OrgSettings
	if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return nil, err
	}

	return &settings, nil
}

// getNextLink extracts the next page URL from the Link header.
// Returns empty string if there is no next page.
func getNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}

	// Link header format: <url>; rel="next", <url>; rel="self"
	parts := strings.Split(linkHeader, ",")
	for _, part := range parts {
		if strings.Contains(part, `rel="next"`) {
			// Extract URL from <url>
			urlPart := strings.TrimSpace(strings.Split(part, ";")[0])
			urlPart = strings.TrimPrefix(urlPart, "<")
			urlPart = strings.TrimSuffix(urlPart, ">")

			// Parse URL and return just the path + query
			u, err := url.Parse(urlPart)
			if err != nil {
				return ""
			}
			if u.RawQuery != "" {
				return u.Path + "?" + u.RawQuery
			}
			return u.Path
		}
	}

	return ""
}

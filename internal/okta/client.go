package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OktaClient defines the interface for Okta API operations.
// This interface allows for easy mocking in tests.
type OktaClient interface {
	// User operations
	FetchUsers(ctx context.Context, callback func([]User) error) error
	FetchUserFactors(ctx context.Context, userID string) ([]Factor, error)
	FetchGroupUsers(ctx context.Context, groupID string, callback func([]User) error) error
	FetchUsersWithRoleAssignments(ctx context.Context, callback func([]RoleAssignedUser) error) error
	FetchUserRoleAssignments(ctx context.Context, userID string) ([]RoleAssignment, error)
	FetchUserGroupIDs(ctx context.Context, userID string) ([]string, error)

	// Application operations
	FetchApplications(ctx context.Context, callback func([]Application) error) error

	// Custom admin roles (Okta Identity Governance feature)
	ListIAMRoles(ctx context.Context) ([]IAMRole, error)
	ListRolePermissions(ctx context.Context, roleID string) ([]string, error)

	// Policy operations
	FetchPolicies(ctx context.Context, policyType string) ([]Policy, error)
	FetchPolicyRules(ctx context.Context, policyID string) ([]PolicyRule, error)

	// Device assurance operations
	FetchDeviceAssurancePolicies(ctx context.Context) ([]DeviceAssurancePolicy, error)

	// Authenticator catalog (org-level enabled factor types)
	ListAuthenticators(ctx context.Context) ([]Authenticator, error)

	// Group operations
	ListGroups(ctx context.Context, callback func([]Group) error) error

	// Network zones, identity providers, API tokens, hooks, and system log
	ListNetworkZones(ctx context.Context) ([]NetworkZone, error)
	ListIdentityProviders(ctx context.Context) ([]IdentityProvider, error)
	ListAPITokens(ctx context.Context) ([]APIToken, error)
	ListEventHooks(ctx context.Context) ([]EventHook, error)
	ListInlineHooks(ctx context.Context) ([]InlineHook, error)
	ListSystemLog(ctx context.Context, filter string, since time.Time, max int) ([]LogEvent, error)

	// Org settings
	FetchOrgSettings(ctx context.Context) (*OrgSettings, error)
	FetchOrgPreferences(ctx context.Context) (*OrgPreferences, error)
	FetchOrgContactUsers(ctx context.Context) ([]OrgContact, error)
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

// FetchGroupUsers fetches all users in a group with pagination.
func (c *Client) FetchGroupUsers(ctx context.Context, groupID string, callback func([]User) error) error {
	path := fmt.Sprintf("/api/v1/groups/%s/users?limit=%d", groupID, paginationLimit)

	for path != "" {
		resp, err := c.doRequest(ctx, "GET", path)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return fmt.Errorf("group users API returned status %d for group %s", resp.StatusCode, groupID)
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

		path = getNextLink(resp.Header.Get("Link"))
	}

	return nil
}

// FetchUsersWithRoleAssignments fetches all users that have role assignments.
func (c *Client) FetchUsersWithRoleAssignments(ctx context.Context, callback func([]RoleAssignedUser) error) error {
	path := fmt.Sprintf("/api/v1/iam/assignees/users?limit=%d", paginationLimit)

	for path != "" {
		resp, err := c.doRequest(ctx, "GET", path)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return fmt.Errorf("role assignees API returned status %d", resp.StatusCode)
		}

		var page RoleAssignedUsersResponse
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			_ = resp.Body.Close()
			return err
		}
		_ = resp.Body.Close()

		if err := callback(page.Value); err != nil {
			return err
		}

		path = ""
		if page.Links.Next != nil && page.Links.Next.Href != "" {
			path = getPathAndQuery(page.Links.Next.Href)
		}
	}

	return nil
}

// FetchUserRoleAssignments fetches all role assignments for a user.
func (c *Client) FetchUserRoleAssignments(ctx context.Context, userID string) ([]RoleAssignment, error) {
	path := fmt.Sprintf("/api/v1/users/%s/roles", userID)

	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user roles API returned status %d for user %s", resp.StatusCode, userID)
	}

	var roles []RoleAssignment
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, err
	}

	return roles, nil
}

// FetchUserGroupIDs fetches the IDs of the groups a user belongs to.
func (c *Client) FetchUserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	var groups []Group
	if err := c.getJSON(ctx, fmt.Sprintf("/api/v1/users/%s/groups", userID), &groups); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	return ids, nil
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

// APIStatusError carries the HTTP status from a non-200 Okta response so callers
// can branch on 403 (scope denied) vs 404 (feature not available) for graceful
// per-surface degradation.
type APIStatusError struct {
	StatusCode int
	Path       string
}

func (e *APIStatusError) Error() string {
	return fmt.Sprintf("okta API %s returned status %d", e.Path, e.StatusCode)
}

// StatusCodeOf returns the HTTP status code from an APIStatusError, or 0 if err
// is not one. Use it to distinguish scope-denied / feature-not-licensed surfaces
// from transient failures.
func StatusCodeOf(err error) int {
	var apiErr *APIStatusError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

// getJSON performs a GET and decodes a 200 body into dest. Non-200 responses
// return an *APIStatusError carrying the status code.
func (c *Client) getJSON(ctx context.Context, path string, dest any) error {
	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &APIStatusError{StatusCode: resp.StatusCode, Path: path}
	}

	return json.NewDecoder(resp.Body).Decode(dest)
}

// ListGroups fetches all groups with pagination, expanding member-count stats.
func (c *Client) ListGroups(ctx context.Context, callback func([]Group) error) error {
	path := fmt.Sprintf("/api/v1/groups?expand=stats&limit=%d", paginationLimit)

	for path != "" {
		resp, err := c.doRequest(ctx, "GET", path)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return &APIStatusError{StatusCode: resp.StatusCode, Path: path}
		}

		var groups []Group
		if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
			_ = resp.Body.Close()
			return err
		}
		_ = resp.Body.Close()

		if err := callback(groups); err != nil {
			return err
		}

		path = getNextLink(resp.Header.Get("Link"))
	}

	return nil
}

// ListAuthenticators fetches the org-level authenticator catalog.
func (c *Client) ListAuthenticators(ctx context.Context) ([]Authenticator, error) {
	var authenticators []Authenticator
	if err := c.getJSON(ctx, "/api/v1/authenticators", &authenticators); err != nil {
		return nil, err
	}
	return authenticators, nil
}

// ListIAMRoles fetches the org's custom administrator roles (Okta Identity
// Governance feature). Returns an *APIStatusError with status 404 when the
// feature is not licensed, which callers treat as a graceful skip.
func (c *Client) ListIAMRoles(ctx context.Context) ([]IAMRole, error) {
	path := fmt.Sprintf("/api/v1/iam/roles?limit=%d", paginationLimit)
	var roles []IAMRole

	for path != "" {
		var page IAMRolesResponse
		if err := c.getJSON(ctx, path, &page); err != nil {
			return nil, err
		}
		roles = append(roles, page.Roles...)

		path = ""
		if page.Links.Next != nil && page.Links.Next.Href != "" {
			path = getPathAndQuery(page.Links.Next.Href)
		}
	}

	return roles, nil
}

// ListRolePermissions fetches the permission labels granted to a custom role.
func (c *Client) ListRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	var resp RolePermissionsResponse
	if err := c.getJSON(ctx, fmt.Sprintf("/api/v1/iam/roles/%s/permissions", roleID), &resp); err != nil {
		return nil, err
	}
	permissions := make([]string, 0, len(resp.Permissions))
	for _, p := range resp.Permissions {
		permissions = append(permissions, p.Label)
	}
	return permissions, nil
}

// FetchDeviceAssurancePolicies fetches all device assurance policies.
func (c *Client) FetchDeviceAssurancePolicies(ctx context.Context) ([]DeviceAssurancePolicy, error) {
	path := "/api/v1/device-assurances"

	resp, err := c.doRequest(ctx, "GET", path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device assurances API returned status %d", resp.StatusCode)
	}

	var policies []DeviceAssurancePolicy
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return nil, err
	}

	return policies, nil
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

// getPathAndQuery extracts the path and query string from an absolute URL.
func getPathAndQuery(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}

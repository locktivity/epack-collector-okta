package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// OktaClient defines the interface for Okta API operations.
// This interface allows for easy mocking in tests.
type OktaClient interface {
	// SignIn proves the credential works before any surface is read.
	SignIn(ctx context.Context) (*Identity, error)

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

// Identity is the principal a client signed in as.
type Identity struct {
	// Kind is "api_token" or "service_app".
	Kind string
	// ID is the API token owner's user ID, or the service app's client ID.
	ID string
	// Scopes lists the OAuth scopes the access token carries.
	Scopes []string
}

// Client wraps the Okta REST API client.
type Client struct {
	httpClient  *http.Client
	baseURL     string
	accessToken string // OAuth 2.0 access token or SSWS token
	authType    string // "Bearer" or "SSWS"
	oauth       *oauthCredentials
}

// Ensure Client implements OktaClient.
var _ OktaClient = (*Client)(nil)

// NewClient creates a new Okta client with API token (SSWS) authentication.
func NewClient(httpClient *http.Client, orgDomain, apiToken string) *Client {
	return &Client{
		httpClient:  httpClient,
		baseURL:     buildBaseURL(orgDomain),
		accessToken: apiToken,
		authType:    "SSWS",
	}
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

// Host returns the host an org's API calls go to, which is the only host
// that may receive its credentials, or "" when orgDomain names no host.
func Host(orgDomain string) string {
	u, err := url.Parse(buildBaseURL(orgDomain))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
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

// SignIn proves the credential works before any surface is read. An API
// token reads the user it belongs to; a service app exchanges its signed
// assertion for an access token.
func (c *Client) SignIn(ctx context.Context) (*Identity, error) {
	if c.oauth != nil {
		return c.exchangeToken(ctx)
	}
	const op = "okta.users.me.get"
	var me struct {
		ID string `json:"id"`
	}
	if _, err := c.get(ctx, op, "/api/v1/users/me", &me); err != nil {
		return nil, err
	}
	if me.ID == "" {
		return nil, invalidResponse(op, "has no user id")
	}
	return &Identity{Kind: "api_token", ID: me.ID}, nil
}

// get sends one named GET and decodes a 200 response into dest. Any other
// status returns an *APIStatusError. The SDK's transport retries the call
// when that is safe.
func (c *Client) get(ctx context.Context, op, path string, dest any) (http.Header, error) {
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
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
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading the response to %s: %w", op, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, newAPIStatusError(resp, path, body)
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return nil, fmt.Errorf("decoding the response to %s: %w", op, err)
	}
	return resp.Header, nil
}

// listPages reads every page of a list endpoint, following the Link header,
// and hands each page to each. A response that carries no list fails the
// read, so a missing list never reads as an empty one.
func listPages[T any](ctx context.Context, c *Client, op, path string, each func([]T) error) error {
	for path != "" {
		var page *[]T
		header, err := c.get(ctx, op, path, &page)
		if err != nil {
			return err
		}
		if page == nil {
			return invalidResponse(op, "has no list")
		}
		if err := each(*page); err != nil {
			return err
		}
		path = getNextLink(header.Get("Link"))
	}
	return nil
}

// listAll reads every page of a list endpoint into one slice.
func listAll[T any](ctx context.Context, c *Client, op, path string) ([]T, error) {
	items := []T{}
	err := listPages(ctx, c, op, path, func(page []T) error {
		items = append(items, page...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

// invalidResponse reports a 200 response that lacks what the collector
// reads from it.
func invalidResponse(op, problem string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("the response to %s %s", op, problem))
}

// FetchUsers fetches all users with pagination.
func (c *Client) FetchUsers(ctx context.Context, callback func([]User) error) error {
	return listPages(ctx, c, "okta.users.list", fmt.Sprintf("/api/v1/users?limit=%d", paginationLimit), callback)
}

// FetchUserFactors fetches all MFA factors for a user. A user with no
// factors has an empty list; any other answer, a 404 included, is an error.
func (c *Client) FetchUserFactors(ctx context.Context, userID string) ([]Factor, error) {
	return listAll[Factor](ctx, c, "okta.users.factors.list", "/api/v1/users/"+url.PathEscape(userID)+"/factors")
}

// FetchGroupUsers fetches all users in a group with pagination.
func (c *Client) FetchGroupUsers(ctx context.Context, groupID string, callback func([]User) error) error {
	path := fmt.Sprintf("/api/v1/groups/%s/users?limit=%d", url.PathEscape(groupID), paginationLimit)
	return listPages(ctx, c, "okta.groups.users.list", path, callback)
}

// FetchUsersWithRoleAssignments fetches all users that have role assignments.
func (c *Client) FetchUsersWithRoleAssignments(ctx context.Context, callback func([]RoleAssignedUser) error) error {
	const op = "okta.iam.assignees.list"
	path := fmt.Sprintf("/api/v1/iam/assignees/users?limit=%d", paginationLimit)

	for path != "" {
		var page RoleAssignedUsersResponse
		if _, err := c.get(ctx, op, path, &page); err != nil {
			return err
		}
		if page.Value == nil {
			return invalidResponse(op, "has no value list")
		}
		if err := callback(*page.Value); err != nil {
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
	return listAll[RoleAssignment](ctx, c, "okta.users.roles.list", "/api/v1/users/"+url.PathEscape(userID)+"/roles")
}

// FetchUserGroupIDs fetches the IDs of the groups a user belongs to.
func (c *Client) FetchUserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	groups, err := listAll[Group](ctx, c, "okta.users.groups.list", "/api/v1/users/"+url.PathEscape(userID)+"/groups")
	if err != nil {
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
	return listPages(ctx, c, "okta.apps.list", fmt.Sprintf("/api/v1/apps?limit=%d", paginationLimit), callback)
}

// FetchPolicies fetches all policies of a given type.
func (c *Client) FetchPolicies(ctx context.Context, policyType string) ([]Policy, error) {
	return listAll[Policy](ctx, c, "okta.policies.list", "/api/v1/policies?type="+url.QueryEscape(policyType))
}

// FetchPolicyRules fetches all rules for a policy.
func (c *Client) FetchPolicyRules(ctx context.Context, policyID string) ([]PolicyRule, error) {
	return listAll[PolicyRule](ctx, c, "okta.policies.rules.list", "/api/v1/policies/"+url.PathEscape(policyID)+"/rules")
}

// APIStatusError carries the HTTP status, headers, and Okta error code of a
// non-200 response, so the SDK can classify it and callers can branch on 403
// (scope denied) vs 404 (feature not available).
type APIStatusError struct {
	StatusCode int
	Path       string
	Header     http.Header
	// Code is Okta's errorCode, such as E0000006.
	Code    string
	Summary string
}

func newAPIStatusError(resp *http.Response, path string, body []byte) *APIStatusError {
	e := &APIStatusError{StatusCode: resp.StatusCode, Path: path, Header: resp.Header}
	var payload struct {
		ErrorCode    string `json:"errorCode"`
		ErrorSummary string `json:"errorSummary"`
	}
	if json.Unmarshal(body, &payload) == nil {
		e.Code = payload.ErrorCode
		e.Summary = payload.ErrorSummary
	}
	return e
}

func (e *APIStatusError) Error() string {
	route, _, _ := strings.Cut(e.Path, "?")
	if e.Code != "" {
		return fmt.Sprintf("okta API %s returned status %d: %s %s", route, e.StatusCode, e.Code, e.Summary)
	}
	return fmt.Sprintf("okta API %s returned status %d", route, e.StatusCode)
}

// HTTPStatus, HTTPHeader, and VendorCode let componentsdk.Classify read the
// status and throttle headers, and give records Okta's error code.
func (e *APIStatusError) HTTPStatus() int         { return e.StatusCode }
func (e *APIStatusError) HTTPHeader() http.Header { return e.Header }
func (e *APIStatusError) VendorCode() string      { return e.Code }

// CollectionCode reads E0000015, which Okta returns with a 401 when the org
// lacks the feature an endpoint belongs to.
func (e *APIStatusError) CollectionCode() componentsdk.Code {
	if e.Code == "E0000015" {
		return componentsdk.CodeNotLicensed
	}
	return ""
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

// ListGroups fetches all groups with pagination, expanding member-count stats.
func (c *Client) ListGroups(ctx context.Context, callback func([]Group) error) error {
	return listPages(ctx, c, "okta.groups.list", fmt.Sprintf("/api/v1/groups?expand=stats&limit=%d", paginationLimit), callback)
}

// ListAuthenticators fetches the org-level authenticator catalog.
func (c *Client) ListAuthenticators(ctx context.Context) ([]Authenticator, error) {
	return listAll[Authenticator](ctx, c, "okta.authenticators.list", "/api/v1/authenticators")
}

// ListIAMRoles fetches the org's custom administrator roles (Okta Identity
// Governance feature). Returns an *APIStatusError with status 404 when the
// feature is not licensed.
func (c *Client) ListIAMRoles(ctx context.Context) ([]IAMRole, error) {
	const op = "okta.iam.roles.list"
	path := fmt.Sprintf("/api/v1/iam/roles?limit=%d", paginationLimit)
	roles := []IAMRole{}

	for path != "" {
		var page IAMRolesResponse
		if _, err := c.get(ctx, op, path, &page); err != nil {
			return nil, err
		}
		if page.Roles == nil {
			return nil, invalidResponse(op, "has no roles list")
		}
		roles = append(roles, *page.Roles...)

		path = ""
		if page.Links.Next != nil && page.Links.Next.Href != "" {
			path = getPathAndQuery(page.Links.Next.Href)
		}
	}

	return roles, nil
}

// ListRolePermissions fetches the permission labels granted to a custom role.
func (c *Client) ListRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	const op = "okta.iam.roles.permissions.list"
	var resp RolePermissionsResponse
	if _, err := c.get(ctx, op, "/api/v1/iam/roles/"+url.PathEscape(roleID)+"/permissions", &resp); err != nil {
		return nil, err
	}
	if resp.Permissions == nil {
		return nil, invalidResponse(op, "has no permissions list")
	}
	permissions := make([]string, 0, len(*resp.Permissions))
	for _, p := range *resp.Permissions {
		permissions = append(permissions, p.Label)
	}
	return permissions, nil
}

// FetchDeviceAssurancePolicies fetches all device assurance policies.
func (c *Client) FetchDeviceAssurancePolicies(ctx context.Context) ([]DeviceAssurancePolicy, error) {
	return listAll[DeviceAssurancePolicy](ctx, c, "okta.device_assurances.list", "/api/v1/device-assurances")
}

// FetchOrgSettings fetches organization settings.
func (c *Client) FetchOrgSettings(ctx context.Context) (*OrgSettings, error) {
	const op = "okta.org.get"
	var settings OrgSettings
	if _, err := c.get(ctx, op, "/api/v1/org", &settings); err != nil {
		return nil, err
	}
	if settings.ID == "" {
		return nil, invalidResponse(op, "has no org id")
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

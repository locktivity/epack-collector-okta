package okta

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
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
	FetchPolicyRules(ctx context.Context, policy Policy) ([]PolicyRule, error)

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
	FetchOrgContactUsers(ctx context.Context) ([]OrgContact, error)
}

// Identity is the principal a client signed in as.
type Identity struct {
	// Kind is "api_token" or "service_app".
	Kind string
	// AuthMethod is how the client proved its identity:
	// componentsdk.AuthAPIToken or componentsdk.AuthPrivateKeyJWT.
	AuthMethod string
	// ID is the API token owner's user ID, or the service app's client ID.
	ID string
	// RequestedScopes lists the OAuth scopes the service app asked for.
	RequestedScopes []string
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
	resp, err := c.get(ctx, op, "/api/v1/users/me", &me)
	if err != nil {
		return nil, err
	}
	if me.ID == "" {
		return nil, invalidResponse(resp, op, "has no user id")
	}
	return &Identity{Kind: "api_token", AuthMethod: componentsdk.AuthAPIToken, ID: me.ID}, nil
}

// get sends one named GET and decodes a 200 response into dest. Any other
// status returns an *APIStatusError. Each error built from the response
// names the call it answered. The SDK's transport retries the call when that
// is safe. The call declares the scope it needs.
func (c *Client) get(ctx context.Context, op, path string, dest any) (*http.Response, error) {
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op, Permission: Scope(op)})
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
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("reading the response to %s: %w", op, err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, componentsdk.ResponseError(resp, newAPIStatusError(resp, path, body))
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("decoding the response to %s: %w", op, err))
	}
	return resp, nil
}

// listResponses reads every page of a list endpoint, following the Link
// header, and hands each page to each with the response that carried it. A
// response that carries no list fails the read, so a missing list never
// reads as an empty one.
func listResponses[T any](ctx context.Context, c *Client, op, path string, each func(*http.Response, []T) error) error {
	pages := readPages{}
	for path != "" {
		var page *[]T
		resp, err := c.get(ctx, op, path, &page)
		if err != nil {
			return err
		}
		if page == nil {
			return invalidResponse(resp, op, "has no list")
		}
		if err := each(resp, *page); err != nil {
			return err
		}
		if path, err = pages.next(resp, op, path, getNextLink(resp)); err != nil {
			return err
		}
	}
	return nil
}

// readPages holds the pages a list read has requested, so a next link back
// to one of them fails the read rather than looping.
type readPages map[string]bool

// next returns the page to read after path, which resp answered, or an
// error when next names a page already read.
func (p readPages) next(resp *http.Response, op, path, next string) (string, error) {
	p[path] = true
	if p[next] {
		return "", invalidResponse(resp, op, "links to a page already read")
	}
	return next, nil
}

// listCheck holds a list read to what Okta always sends. item names what
// an item lacks of the fields Okta sends in each one, or returns "" for an
// item the collector can read. none, when set, says why an empty list is
// wrong, and an empty one fails the read with it, with noneCode, or
// invalid_response when noneCode is "".
type listCheck[T any] struct {
	item     func(T) string
	none     string
	noneCode componentsdk.Code
}

// listPages is listResponses for a list that check holds, and hands each
// page to each. An item check finds a problem with fails the read, since a
// list read in part would stand in for the whole.
func listPages[T any](ctx context.Context, c *Client, op, path string, check listCheck[T], each func([]T) error) error {
	var last *http.Response
	listed := 0
	err := listResponses(ctx, c, op, path, func(resp *http.Response, page []T) error {
		if check.item != nil {
			for _, item := range page {
				if problem := check.item(item); problem != "" {
					return invalidResponse(resp, op, problem)
				}
			}
		}
		last, listed = resp, listed+len(page)
		return each(page)
	})
	if err == nil && listed == 0 && check.none != "" {
		return responseProblem(last, cmp.Or(check.noneCode, componentsdk.CodeInvalidResponse), op, check.none)
	}
	return err
}

// listAll reads every page of a list endpoint into one slice, which check
// holds.
func listAll[T any](ctx context.Context, c *Client, op, path string, check listCheck[T]) ([]T, error) {
	items := []T{}
	err := listPages(ctx, c, op, path, check, func(page []T) error {
		items = append(items, page...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

// decodeItems decodes each item of a page, which resp carried, and fails
// with the problem check finds with one. check gets the item as Okta sent
// it too, for a field whose zero value is also a value.
func decodeItems[T any](resp *http.Response, op string, page []json.RawMessage, check func(T, json.RawMessage) string) ([]T, error) {
	items := make([]T, len(page))
	for i, raw := range page {
		if err := json.Unmarshal(raw, &items[i]); err != nil {
			return nil, componentsdk.ResponseError(resp, fmt.Errorf("decoding the response to %s: %w", op, err))
		}
		if problem := check(items[i], raw); problem != "" {
			return nil, invalidResponse(resp, op, problem)
		}
	}
	return items, nil
}

// invalidResponse reports a 200 response that lacks what the collector
// reads from it, as an error about the call resp answered.
func invalidResponse(resp *http.Response, op, problem string) error {
	return responseProblem(resp, componentsdk.CodeInvalidResponse, op, problem)
}

// responseProblem reports a problem with a 200 response, with code, as an
// error about the call resp answered.
func responseProblem(resp *http.Response, code componentsdk.Code, op, problem string) error {
	return componentsdk.ResponseError(resp, componentsdk.CodeError(code, fmt.Errorf("the response to %s %s", op, problem)))
}

// noSuperAdmin is why a list of users is never empty: every org has at
// least one individually assigned super admin.
const noSuperAdmin = "lists no users, and every org has at least one super admin"

// FetchUsers fetches all users with pagination. A user with no status, or
// an empty list, fails the read.
func (c *Client) FetchUsers(ctx context.Context, callback func([]User) error) error {
	check := listCheck[User]{none: noSuperAdmin, item: func(u User) string {
		if u.Status == "" {
			return "lists a user with no status"
		}
		return ""
	}}
	return listPages(ctx, c, "okta.users.list", fmt.Sprintf("/api/v1/users?limit=%d", paginationLimit), check, callback)
}

// FetchUserFactors fetches all MFA factors for a user. A user with no
// factors has an empty list; any other answer, a 404 included, is an error,
// and so is a factor with no type or status.
func (c *Client) FetchUserFactors(ctx context.Context, userID string) ([]Factor, error) {
	check := listCheck[Factor]{item: func(f Factor) string {
		if f.FactorType == "" || f.Status == "" {
			return "lists a factor with no factorType or status"
		}
		return ""
	}}
	return listAll(ctx, c, "okta.users.factors.list", "/api/v1/users/"+url.PathEscape(userID)+"/factors", check)
}

// FetchGroupUsers fetches all users in a group with pagination. A member
// with no id fails the read, since policies match people by it.
func (c *Client) FetchGroupUsers(ctx context.Context, groupID string, callback func([]User) error) error {
	path := fmt.Sprintf("/api/v1/groups/%s/users?limit=%d", url.PathEscape(groupID), paginationLimit)
	check := listCheck[User]{item: func(u User) string {
		if u.ID == "" {
			return "lists a member with no id"
		}
		return ""
	}}
	return listPages(ctx, c, "okta.groups.users.list", path, check, callback)
}

// FetchUsersWithRoleAssignments fetches all users that have role
// assignments. A user with no id, or an empty list, fails the read: every
// org's super admin holds a role.
func (c *Client) FetchUsersWithRoleAssignments(ctx context.Context, callback func([]RoleAssignedUser) error) error {
	const op = "okta.iam.assignees.list"
	path := fmt.Sprintf("/api/v1/iam/assignees/users?limit=%d", paginationLimit)

	pages := readPages{}
	listed := 0
	for path != "" {
		var page RoleAssignedUsersResponse
		resp, err := c.get(ctx, op, path, &page)
		if err != nil {
			return err
		}
		if page.Value == nil {
			return invalidResponse(resp, op, "has no value list")
		}
		if slices.ContainsFunc(*page.Value, func(u RoleAssignedUser) bool { return u.ID == "" }) {
			return invalidResponse(resp, op, "lists a user with no id")
		}
		listed += len(*page.Value)
		if err := callback(*page.Value); err != nil {
			return err
		}

		next := ""
		if page.Links.Next != nil && page.Links.Next.Href != "" {
			next = getPathAndQuery(page.Links.Next.Href)
		}
		if next == "" && listed == 0 {
			return invalidResponse(resp, op, noSuperAdmin)
		}
		if path, err = pages.next(resp, op, path, next); err != nil {
			return err
		}
	}

	return nil
}

// FetchUserRoleAssignments fetches all role assignments for a user the
// role assignees list names. An empty list fails the read, since that user
// holds a role, and so does a role with no type, or a custom role that
// names no role ID.
func (c *Client) FetchUserRoleAssignments(ctx context.Context, userID string) ([]RoleAssignment, error) {
	check := listCheck[RoleAssignment]{none: "lists no roles for a user the role assignees list names", item: func(r RoleAssignment) string {
		if r.Type == "" || (strings.EqualFold(r.Type, "CUSTOM") && r.Role == "") {
			return "lists a role with no type, or a custom role with no role ID"
		}
		return ""
	}}
	return listAll(ctx, c, "okta.users.roles.list", "/api/v1/users/"+url.PathEscape(userID)+"/roles", check)
}

// FetchUserGroupIDs fetches the IDs of the groups a user belongs to.
func (c *Client) FetchUserGroupIDs(ctx context.Context, userID string) ([]string, error) {
	groups, err := listAll(ctx, c, "okta.users.groups.list", "/api/v1/users/"+url.PathEscape(userID)+"/groups", listCheck[Group]{})
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	return ids, nil
}

// FetchApplications fetches all applications with pagination. An app with
// no status, sign-on mode, or features list fails the read. Okta sends an
// app with no features an empty list.
func (c *Client) FetchApplications(ctx context.Context, callback func([]Application) error) error {
	check := listCheck[Application]{item: func(a Application) string {
		if a.Status == "" || a.SignOnMode == "" || a.Features == nil {
			return "lists an app with no status, signOnMode, or features"
		}
		return ""
	}}
	return listPages(ctx, c, "okta.apps.list", fmt.Sprintf("/api/v1/apps?limit=%d", paginationLimit), check, callback)
}

// FetchPolicies fetches all policies of a given type. Okta scopes each
// sign-on, MFA enrollment and password policy to the groups it includes,
// and the default policy includes the Everyone group. An active policy that
// includes no group fails the read, since who it applies to is unknown. So
// does a policy with no status or priority, and an empty list: Okta creates
// a default policy of each type, which can't be deleted.
func (c *Client) FetchPolicies(ctx context.Context, policyType string) ([]Policy, error) {
	const op = "okta.policies.list"
	policies := []Policy{}
	var last *http.Response
	err := listResponses(ctx, c, op, "/api/v1/policies?type="+url.QueryEscape(policyType), func(resp *http.Response, page []json.RawMessage) error {
		read, err := decodeItems(resp, op, page, func(p Policy, raw json.RawMessage) string {
			var sent struct {
				Priority *int `json:"priority"`
			}
			_ = json.Unmarshal(raw, &sent)
			switch {
			case p.Status == "" || sent.Priority == nil:
				return "lists a policy with no status or priority"
			// An IdP routing policy applies to every sign-in and names no
			// group.
			case p.Status == "ACTIVE" && policyType != "IDP_DISCOVERY" && !p.Conditions.People.includesGroups():
				return "has an active policy that includes no group"
			}
			return ""
		})
		if err != nil {
			return err
		}
		last, policies = resp, append(policies, read...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// No IdP routing policy reads as Okta's default routing rule would,
	// leaving every sign-in to Okta.
	if len(policies) == 0 && policyType != "IDP_DISCOVERY" {
		return nil, invalidResponse(last, op, "lists no policies, and Okta creates a default policy of each type")
	}
	return policies, nil
}

// FetchPolicyRules fetches all rules for a policy. A policy can have no
// rules, and Okta then never applies it, but a default policy always has
// its default rule. A rule with no status fails the read, and so does a
// sign-on rule with no signon access, or one that allows sign-in with no
// requireFactor or session settings, and a password rule that doesn't say
// whether it allows self-service reset and unlock. Okta sends all of them
// in each rule.
func (c *Client) FetchPolicyRules(ctx context.Context, policy Policy) ([]PolicyRule, error) {
	const op = "okta.policies.rules.list"
	rules := []PolicyRule{}
	var last *http.Response
	err := listResponses(ctx, c, op, "/api/v1/policies/"+url.PathEscape(policy.ID)+"/rules", func(resp *http.Response, page []json.RawMessage) error {
		read, err := decodeItems(resp, op, page, func(r PolicyRule, raw json.RawMessage) string {
			switch {
			case r.Status == "":
				return "lists a rule with no status"
			case policy.Type == "OKTA_SIGN_ON":
				return signonProblem(r, raw)
			case policy.Type == "PASSWORD" && (r.Actions.SelfServicePasswordReset == nil || r.Actions.SelfServicePasswordReset.Access == "" ||
				r.Actions.SelfServiceUnlock == nil || r.Actions.SelfServiceUnlock.Access == ""):
				return "lists a password rule with no selfServicePasswordReset or selfServiceUnlock access"
			}
			return ""
		})
		if err != nil {
			return err
		}
		last, rules = resp, append(rules, read...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 && policy.System {
		return nil, invalidResponse(last, op, "lists no rules for a default policy, which always has its default rule")
	}
	return rules, nil
}

// signonProblem names what a sign-on rule lacks of the signon action Okta
// sends in each one, or returns "". false and 0 are values of
// requireFactor and the session settings, so the rule as Okta sent it says
// whether they are there.
func signonProblem(r PolicyRule, raw json.RawMessage) string {
	if r.Actions.Signon == nil || r.Actions.Signon.Access == "" {
		return "lists a sign-on rule with no signon access"
	}
	if r.Actions.Signon.Access != "ALLOW" {
		return ""
	}
	var sent struct {
		Actions struct {
			Signon struct {
				RequireFactor *bool `json:"requireFactor"`
				Session       struct {
					UsePersistentCookie       *bool `json:"usePersistentCookie"`
					MaxSessionIdleMinutes     *int  `json:"maxSessionIdleMinutes"`
					MaxSessionLifetimeMinutes *int  `json:"maxSessionLifetimeMinutes"`
				} `json:"session"`
			} `json:"signon"`
		} `json:"actions"`
	}
	_ = json.Unmarshal(raw, &sent)
	signon := sent.Actions.Signon
	if signon.RequireFactor == nil || signon.Session.UsePersistentCookie == nil ||
		signon.Session.MaxSessionIdleMinutes == nil || signon.Session.MaxSessionLifetimeMinutes == nil {
		return "lists a sign-on rule that allows sign-in with no requireFactor or session settings"
	}
	return ""
}

// VendorCode reads Okta's code for a failed response, for
// componentsdk.HTTPOptions.VendorCode: a management API error's errorCode,
// such as E0000047 for a rate limit, or the OAuth error the token endpoint
// answers with, such as invalid_client.
func VendorCode(_ *http.Response, body []byte) string {
	var payload struct {
		ErrorCode string `json:"errorCode"`
		Error     string `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	if payload.ErrorCode != "" {
		return payload.ErrorCode
	}
	return payload.Error
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

// ListGroups fetches all groups with pagination, expanding member-count
// stats. A group with no type fails the read. So does an empty list, with
// permission_denied: every org has the built-in Everyone group, and Okta
// doesn't list it for a group admin, so the admin the collector signs in as
// can't see the groups.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tags/group/other/listgroups
func (c *Client) ListGroups(ctx context.Context, callback func([]Group) error) error {
	check := listCheck[Group]{
		none:     "lists no groups, and every org has the Everyone group, which Okta doesn't list for a group admin",
		noneCode: componentsdk.CodePermissionDenied,
		item: func(g Group) string {
			if g.Type == "" {
				return "lists a group with no type"
			}
			return ""
		},
	}
	return listPages(ctx, c, "okta.groups.list", fmt.Sprintf("/api/v1/groups?expand=stats&limit=%d", paginationLimit), check, callback)
}

// ListAuthenticators fetches the org-level authenticator catalog. An
// authenticator with no key or status, or an empty catalog, fails the read:
// Okta lists each authenticator, inactive ones too, and the password
// authenticator is active by default.
func (c *Client) ListAuthenticators(ctx context.Context) ([]Authenticator, error) {
	check := listCheck[Authenticator]{none: "lists no authenticators, and Okta lists each one, inactive ones too", item: func(a Authenticator) string {
		if a.Key == "" || a.Status == "" {
			return "lists an authenticator with no key or status"
		}
		return ""
	}}
	return listAll(ctx, c, "okta.authenticators.list", "/api/v1/authenticators", check)
}

// ListIAMRoles fetches the org's custom administrator roles (Okta Identity
// Governance feature). Returns an *APIStatusError with status 404 when the
// feature is not licensed. A role with no id fails the read, since its
// permissions can't be read.
func (c *Client) ListIAMRoles(ctx context.Context) ([]IAMRole, error) {
	const op = "okta.iam.roles.list"
	path := fmt.Sprintf("/api/v1/iam/roles?limit=%d", paginationLimit)
	roles := []IAMRole{}

	pages := readPages{}
	for path != "" {
		var page IAMRolesResponse
		resp, err := c.get(ctx, op, path, &page)
		if err != nil {
			return nil, err
		}
		if page.Roles == nil {
			return nil, invalidResponse(resp, op, "has no roles list")
		}
		if slices.ContainsFunc(*page.Roles, func(r IAMRole) bool { return r.ID == "" }) {
			return nil, invalidResponse(resp, op, "lists a role with no id")
		}
		roles = append(roles, *page.Roles...)

		next := ""
		if page.Links.Next != nil && page.Links.Next.Href != "" {
			next = getPathAndQuery(page.Links.Next.Href)
		}
		if path, err = pages.next(resp, op, path, next); err != nil {
			return nil, err
		}
	}

	return roles, nil
}

// ListRolePermissions fetches the permission labels granted to a custom
// role. A response with no permissions list fails the read. An empty list
// is a role that grants nothing.
func (c *Client) ListRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	const op = "okta.iam.roles.permissions.list"
	var page RolePermissionsResponse
	resp, err := c.get(ctx, op, "/api/v1/iam/roles/"+url.PathEscape(roleID)+"/permissions", &page)
	if err != nil {
		return nil, err
	}
	if page.Permissions == nil {
		return nil, invalidResponse(resp, op, "has no permissions list")
	}
	permissions := make([]string, 0, len(*page.Permissions))
	for _, p := range *page.Permissions {
		permissions = append(permissions, p.Label)
	}
	return permissions, nil
}

// FetchDeviceAssurancePolicies fetches all device assurance policies.
func (c *Client) FetchDeviceAssurancePolicies(ctx context.Context) ([]DeviceAssurancePolicy, error) {
	return listAll(ctx, c, "okta.device_assurances.list", "/api/v1/device-assurances", listCheck[DeviceAssurancePolicy]{})
}

// FetchOrgSettings fetches organization settings.
func (c *Client) FetchOrgSettings(ctx context.Context) (*OrgSettings, error) {
	const op = "okta.org.get"
	var settings OrgSettings
	resp, err := c.get(ctx, op, "/api/v1/org", &settings)
	if err != nil {
		return nil, err
	}
	if settings.ID == "" {
		return nil, invalidResponse(resp, op, "has no org id")
	}
	return &settings, nil
}

// getNextLink returns the path and query of the next page that resp's Link
// headers name, or "" when there is no next page. Okta sends the self and
// next links as separate Link headers, so every header line is read.
func getNextLink(resp *http.Response) string {
	next, ok := componentsdk.NextLink(resp)
	if !ok {
		return ""
	}
	if next.RawQuery != "" {
		return next.Path + "?" + next.RawQuery
	}
	return next.Path
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

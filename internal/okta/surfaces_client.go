package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ListNetworkZones fetches all network zones with pagination.
func (c *Client) ListNetworkZones(ctx context.Context) ([]NetworkZone, error) {
	return paginateList[NetworkZone](ctx, c, fmt.Sprintf("/api/v1/zones?limit=%d", paginationLimit))
}

// ListIdentityProviders fetches all federation identity providers.
func (c *Client) ListIdentityProviders(ctx context.Context) ([]IdentityProvider, error) {
	return paginateList[IdentityProvider](ctx, c, fmt.Sprintf("/api/v1/idps?limit=%d", paginationLimit))
}

// ListAPITokens fetches all SSWS API tokens. Requires a SUPER_ADMIN-level scope;
// returns an *APIStatusError (403) otherwise.
func (c *Client) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	var tokens []APIToken
	if err := c.getJSON(ctx, "/api/v1/api-tokens", &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// ListEventHooks fetches all event hooks.
func (c *Client) ListEventHooks(ctx context.Context) ([]EventHook, error) {
	var hooks []EventHook
	if err := c.getJSON(ctx, "/api/v1/eventHooks", &hooks); err != nil {
		return nil, err
	}
	return hooks, nil
}

// ListInlineHooks fetches all inline hooks.
func (c *Client) ListInlineHooks(ctx context.Context) ([]InlineHook, error) {
	var hooks []InlineHook
	if err := c.getJSON(ctx, "/api/v1/inlineHooks", &hooks); err != nil {
		return nil, err
	}
	return hooks, nil
}

// ListSystemLog fetches System Log events matching filter since the given time,
// newest first, stopping once max events are collected.
func (c *Client) ListSystemLog(ctx context.Context, filter string, since time.Time, max int) ([]LogEvent, error) {
	q := url.Values{}
	q.Set("since", since.UTC().Format(time.RFC3339))
	q.Set("sortOrder", "DESCENDING")
	q.Set("limit", strconv.Itoa(paginationLimit))
	if filter != "" {
		q.Set("filter", filter)
	}
	path := "/api/v1/logs?" + q.Encode()

	var events []LogEvent
	for path != "" && len(events) < max {
		resp, err := c.doRequest(ctx, "GET", path)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, &APIStatusError{StatusCode: resp.StatusCode, Path: path}
		}

		var page []LogEvent
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		_ = resp.Body.Close()

		events = append(events, page...)
		path = getNextLink(resp.Header.Get("Link"))
	}

	if len(events) > max {
		events = events[:max]
	}
	return events, nil
}

// FetchOrgPreferences fetches org-level preferences.
func (c *Client) FetchOrgPreferences(ctx context.Context) (*OrgPreferences, error) {
	var prefs OrgPreferences
	if err := c.getJSON(ctx, "/api/v1/org/preferences", &prefs); err != nil {
		return nil, err
	}
	return &prefs, nil
}

// FetchOrgContactUsers fetches the logins of the org's billing and technical
// contacts. Missing or forbidden contact types are skipped.
func (c *Client) FetchOrgContactUsers(ctx context.Context) ([]OrgContact, error) {
	var contacts []OrgContact
	for _, contactType := range []string{"BILLING", "TECHNICAL"} {
		var user struct {
			Profile struct {
				Login string `json:"login"`
			} `json:"profile"`
		}
		if err := c.getJSON(ctx, "/api/v1/org/contacts/"+contactType, &user); err != nil {
			continue
		}
		if user.Profile.Login != "" {
			contacts = append(contacts, OrgContact{Login: user.Profile.Login})
		}
	}
	return contacts, nil
}

// paginateList fetches a Link-header-paginated array endpoint into a typed slice.
func paginateList[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var items []T
	for path != "" {
		resp, err := c.doRequest(ctx, "GET", path)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, &APIStatusError{StatusCode: resp.StatusCode, Path: path}
		}

		var page []T
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		_ = resp.Body.Close()

		items = append(items, page...)
		path = getNextLink(resp.Header.Get("Link"))
	}
	return items, nil
}

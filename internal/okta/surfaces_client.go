package okta

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// ListNetworkZones fetches all network zones with pagination.
func (c *Client) ListNetworkZones(ctx context.Context) ([]NetworkZone, error) {
	return listAll[NetworkZone](ctx, c, "okta.zones.list", fmt.Sprintf("/api/v1/zones?limit=%d", paginationLimit))
}

// ListIdentityProviders fetches all federation identity providers.
func (c *Client) ListIdentityProviders(ctx context.Context) ([]IdentityProvider, error) {
	return listAll[IdentityProvider](ctx, c, "okta.idps.list", fmt.Sprintf("/api/v1/idps?limit=%d", paginationLimit))
}

// ListAPITokens fetches all SSWS API tokens. Requires a SUPER_ADMIN-level scope;
// returns an *APIStatusError (403) otherwise.
func (c *Client) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	return listAll[APIToken](ctx, c, "okta.api_tokens.list", "/api/v1/api-tokens")
}

// ListEventHooks fetches all event hooks.
func (c *Client) ListEventHooks(ctx context.Context) ([]EventHook, error) {
	return listAll[EventHook](ctx, c, "okta.event_hooks.list", "/api/v1/eventHooks")
}

// ListInlineHooks fetches all inline hooks.
func (c *Client) ListInlineHooks(ctx context.Context) ([]InlineHook, error) {
	return listAll[InlineHook](ctx, c, "okta.inline_hooks.list", "/api/v1/inlineHooks")
}

// ListSystemLog fetches System Log events matching filter since the given time,
// newest first, stopping once max events are collected.
func (c *Client) ListSystemLog(ctx context.Context, filter string, since time.Time, max int) ([]LogEvent, error) {
	const op = "okta.logs.list"
	q := url.Values{}
	q.Set("since", since.UTC().Format(time.RFC3339))
	q.Set("sortOrder", "DESCENDING")
	q.Set("limit", strconv.Itoa(paginationLimit))
	if filter != "" {
		q.Set("filter", filter)
	}
	path := "/api/v1/logs?" + q.Encode()

	events := []LogEvent{}
	for path != "" && len(events) < max {
		var page *[]LogEvent
		header, err := c.get(ctx, op, path, &page)
		if err != nil {
			return nil, err
		}
		if page == nil {
			return nil, invalidResponse(op, "has no list")
		}
		events = append(events, *page...)
		path = getNextLink(header.Get("Link"))
	}

	if len(events) > max {
		events = events[:max]
	}
	return events, nil
}

// FetchOrgPreferences fetches org-level preferences. A response without
// selfServiceUnlock is an error rather than a false.
func (c *Client) FetchOrgPreferences(ctx context.Context) (*OrgPreferences, error) {
	const op = "okta.org.preferences.get"
	var prefs struct {
		SelfServiceUnlock *bool `json:"selfServiceUnlock"`
	}
	if _, err := c.get(ctx, op, "/api/v1/org/preferences", &prefs); err != nil {
		return nil, err
	}
	if prefs.SelfServiceUnlock == nil {
		return nil, invalidResponse(op, "has no selfServiceUnlock")
	}
	return &OrgPreferences{SelfServiceUnlock: *prefs.SelfServiceUnlock}, nil
}

// FetchOrgContactUsers fetches the user IDs of the org's billing and technical
// contacts. Okta answers each contact type with the contact's user ID.
func (c *Client) FetchOrgContactUsers(ctx context.Context) ([]OrgContact, error) {
	const op = "okta.org.contacts.get"
	contacts := make([]OrgContact, 0, 2)
	for _, contactType := range []string{"BILLING", "TECHNICAL"} {
		var contact struct {
			UserID string `json:"userId"`
		}
		if _, err := c.get(ctx, op, "/api/v1/org/contacts/"+contactType, &contact); err != nil {
			return nil, err
		}
		if contact.UserID == "" {
			return nil, invalidResponse(op, "has no userId")
		}
		contacts = append(contacts, OrgContact{Type: contactType, UserID: contact.UserID})
	}
	return contacts, nil
}

package okta

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"time"
)

// ListNetworkZones fetches all network zones with pagination. A zone with
// no type, or an empty list, fails the read: every org has Okta's system
// zones.
func (c *Client) ListNetworkZones(ctx context.Context) ([]NetworkZone, error) {
	check := listCheck[NetworkZone]{none: "lists no zones, and every org has Okta's system zones", item: func(z NetworkZone) string {
		if z.Type == "" {
			return "lists a zone with no type"
		}
		return ""
	}}
	return listAll(ctx, c, "okta.zones.list", fmt.Sprintf("/api/v1/zones?limit=%d", paginationLimit), check)
}

// ListIdentityProviders fetches all federation identity providers. A
// provider with no type or JIT provisioning action fails the read.
func (c *Client) ListIdentityProviders(ctx context.Context) ([]IdentityProvider, error) {
	check := listCheck[IdentityProvider]{item: func(idp IdentityProvider) string {
		if idp.Type == "" || idp.Policy.Provisioning.Action == "" {
			return "lists an identity provider with no type or provisioning action"
		}
		return ""
	}}
	return listAll(ctx, c, "okta.idps.list", fmt.Sprintf("/api/v1/idps?limit=%d", paginationLimit), check)
}

// ListAPITokens fetches all SSWS API tokens. Requires a SUPER_ADMIN-level scope;
// returns an *APIStatusError (403) otherwise. A token with no lastUpdated
// fails the read, and so does an empty list when the client signs in with
// a token, since Okta lists every active token.
func (c *Client) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	check := listCheck[APIToken]{item: func(t APIToken) string {
		if t.LastUpdated.IsZero() {
			return "lists a token with no lastUpdated"
		}
		return ""
	}}
	if c.oauth == nil {
		check.none = "lists no tokens, and the token the collector signs in with is one"
	}
	return listAll(ctx, c, "okta.api_tokens.list", "/api/v1/api-tokens", check)
}

// hookStatus checks that a hook has its status, which says whether Okta
// calls it.
func hookStatus(status string) string {
	if status == "" {
		return "lists a hook with no status"
	}
	return ""
}

// ListEventHooks fetches all event hooks. A hook with no status fails the
// read.
func (c *Client) ListEventHooks(ctx context.Context) ([]EventHook, error) {
	check := listCheck[EventHook]{item: func(h EventHook) string { return hookStatus(h.Status) }}
	return listAll(ctx, c, "okta.event_hooks.list", "/api/v1/eventHooks", check)
}

// ListInlineHooks fetches all inline hooks. A hook with no status fails the
// read.
func (c *Client) ListInlineHooks(ctx context.Context) ([]InlineHook, error) {
	check := listCheck[InlineHook]{item: func(h InlineHook) string { return hookStatus(h.Status) }}
	return listAll(ctx, c, "okta.inline_hooks.list", "/api/v1/inlineHooks", check)
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
	pages := readPages{}
	for path != "" && len(events) < max {
		var page *[]LogEvent
		resp, err := c.get(ctx, op, path, &page)
		if err != nil {
			return nil, err
		}
		if page == nil {
			return nil, invalidResponse(resp, op, "has no list")
		}
		if slices.ContainsFunc(*page, func(e LogEvent) bool { return e.EventType == "" }) {
			return nil, invalidResponse(resp, op, "lists an event with no eventType")
		}
		// Okta can offer a next page of the System Log when no events
		// remain, so an empty page ends the read.
		if len(*page) == 0 {
			break
		}
		events = append(events, *page...)
		if path, err = pages.next(resp, op, path, getNextLink(resp)); err != nil {
			return nil, err
		}
	}

	if len(events) > max {
		events = events[:max]
	}
	return events, nil
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
		resp, err := c.get(ctx, op, "/api/v1/org/contacts/"+contactType, &contact)
		if err != nil {
			return nil, err
		}
		if contact.UserID == "" {
			return nil, invalidResponse(resp, op, "has no userId")
		}
		contacts = append(contacts, OrgContact{Type: contactType, UserID: contact.UserID})
	}
	return contacts, nil
}

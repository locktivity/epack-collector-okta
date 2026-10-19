package okta

import (
	"encoding/json"
	"time"
)

// NetworkZone represents an Okta network zone (GET /api/v1/zones). The gateways,
// proxies, and locations members vary in shape across zone types (IP / DYNAMIC /
// DYNAMIC_V2), so they are held as raw JSON and decoded defensively by the
// collector rather than pinned to one struct shape.
type NetworkZone struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`   // IP, DYNAMIC, DYNAMIC_V2
	Status    string          `json:"status"` // ACTIVE, INACTIVE
	Usage     string          `json:"usage"`  // POLICY, BLOCKLIST
	Gateways  json.RawMessage `json:"gateways"`
	Proxies   json.RawMessage `json:"proxies"`
	Locations json.RawMessage `json:"locations"`
	Asns      json.RawMessage `json:"asns"`
}

// IdentityProvider represents a federation IdP (GET /api/v1/idps).
type IdentityProvider struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`   // SAML2, OIDC, GOOGLE, MICROSOFT, FACEBOOK, etc.
	Status   string `json:"status"` // ACTIVE, INACTIVE
	Protocol struct {
		Type      string `json:"type"`
		Endpoints struct {
			SSO struct {
				URL string `json:"url"`
			} `json:"sso"`
		} `json:"endpoints"`
		Credentials struct {
			Trust struct {
				Issuer string `json:"issuer"`
				Kid    string `json:"kid"`
			} `json:"trust"`
		} `json:"credentials"`
	} `json:"protocol"`
	Policy struct {
		Provisioning struct {
			Action string `json:"action"` // AUTO, DISABLED (JIT provisioning)
			Groups struct {
				Action      string   `json:"action"`
				Assignments []string `json:"assignments"`
			} `json:"groups"`
		} `json:"provisioning"`
		AccountLink struct {
			Action string `json:"action"`
		} `json:"accountLink"`
	} `json:"policy"`
}

// APIToken represents an SSWS API token (GET /api/v1/api-tokens).
type APIToken struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"` // ACTIVE, REVOKED
	Created     time.Time `json:"created"`
	LastUpdated time.Time `json:"lastUpdated"`
	UserID      string    `json:"userId"`
	ClientName  string    `json:"clientName"`
	Network     struct {
		Connection string   `json:"connection"`
		Include    []string `json:"include"`
	} `json:"network"`
}

// EventHook represents an Okta event hook (GET /api/v1/eventHooks).
type EventHook struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // ACTIVE, INACTIVE
	Events struct {
		Type  string   `json:"type"`
		Items []string `json:"items"`
	} `json:"events"`
	Channel HookChannel `json:"channel"`
}

// InlineHook represents an Okta inline hook (GET /api/v1/inlineHooks).
type InlineHook struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Status  string      `json:"status"`
	Type    string      `json:"type"` // com.okta.oauth2.tokens.transform, etc.
	Channel HookChannel `json:"channel"`
}

// HookChannel is the delivery channel for an event or inline hook. The auth
// headers and full config carry secrets and must never be emitted.
type HookChannel struct {
	Type   string `json:"type"`
	Config struct {
		URI     string `json:"uri"`
		Headers []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"headers"`
	} `json:"config"`
}

// LogEvent represents a System Log event (GET /api/v1/logs).
type LogEvent struct {
	UUID      string    `json:"uuid"`
	Published time.Time `json:"published"`
	EventType string    `json:"eventType"`
	Outcome   struct {
		Result string `json:"result"`
	} `json:"outcome"`
	Actor struct {
		AlternateID string `json:"alternateId"`
		Type        string `json:"type"`
	} `json:"actor"`
	Client struct {
		IPAddress string `json:"ipAddress"`
		UserAgent struct {
			RawUserAgent string `json:"rawUserAgent"`
		} `json:"userAgent"`
	} `json:"client"`
	Target []struct {
		DisplayName string `json:"displayName"`
		Type        string `json:"type"`
	} `json:"target"`
}

// OrgContact is an org contact (GET /api/v1/org/contacts/{type}): the
// contact type and the ID of the user who holds it.
type OrgContact struct {
	Type   string `json:"type"`
	UserID string `json:"userId"`
}

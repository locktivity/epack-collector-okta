package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// recentlyUsedWindow bounds the "recently used" SSWS token count at trust level.
const recentlyUsedWindow = 30 * 24 * time.Hour

// APITokens is the SSWS API-token surface. SSWS is the legacy auth method;
// reading tokens requires a SUPER_ADMIN-level scope.
//
// Collected at audit and above; trust omits it.
//
// Audit: active token count + recently-used (30d) count + per-token ID + name +
// status + created-at.
// Internal: + created-by login + last-used + network-zone scope.
//
// Hard rule: token secret values are not exposed by the Okta API and are never
// emitted.
type APITokens struct {
	TotalActiveCount  int `json:"total_active_count"`
	RecentlyUsedCount int `json:"recently_used_count"`

	Inventory []APITokenSummary `json:"inventory,omitempty"`
}

// APITokenSummary is a per-token row (audit+).
type APITokenSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at,omitempty"`

	// Internal-level fields.
	CreatedByLogin    string `json:"created_by_login,omitempty"`
	LastUsedAt        string `json:"last_used_at,omitempty"`
	NetworkZoneScoped *bool  `json:"network_zone_scoped,omitempty"`
}

func (c *Collector) collectAPITokens(ctx context.Context, level componentsdk.Level, users *userMetricsCollector) *APITokens {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}
	tokens, err := c.client.ListAPITokens(ctx)
	if err != nil {
		err = c.warnSurfaceRole("api tokens", "okta.apiTokens.read", "the SUPER_ADMIN role", err)
		c.gaps.notCollected(err, "/api_tokens")
		return nil
	}

	recentThreshold := c.config.now().Add(-recentlyUsedWindow)
	out := &APITokens{}
	for _, t := range tokens {
		if t.Status == StatusActive {
			out.TotalActiveCount++
			if t.LastUpdated.After(recentThreshold) {
				out.RecentlyUsedCount++
			}
		}
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out
	}

	loginByID := users.loginByID()
	out.Inventory = make([]APITokenSummary, 0, len(tokens))
	for i, t := range tokens {
		row := APITokenSummary{ID: t.ID, Name: t.Name, Status: t.Status, CreatedAt: formatTime(t.Created)}
		if level.AtLeast(componentsdk.LevelInternal) {
			if users.err != nil && t.UserID != "" {
				c.gaps.notCollected(users.err, rowPointer("/api_tokens/inventory", i, "created_by_login"))
			}
			row.CreatedByLogin = loginByID[t.UserID]
			row.LastUsedAt = formatTime(t.LastUpdated)
			scoped := len(t.Network.Include) > 0
			row.NetworkZoneScoped = &scoped
		}
		out.Inventory = append(out.Inventory, row)
	}

	return out
}

package collector

import (
	"context"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// Hooks is the event-hook + inline-hook surface.
//
// Collected at audit and above; trust omits it.
//
// Audit: counts + count by status + per-hook name + type + status + subscribed events.
// Internal: + endpoint host (host only) + channel type.
//
// Hard rule: hook authentication headers, full hook URLs, and hook secrets are
// never emitted. Only the endpoint host is surfaced, at internal.
type Hooks struct {
	EventHookCount  int `json:"event_hook_count"`
	InlineHookCount int `json:"inline_hook_count"`
	ActiveCount     int `json:"active_count"`
	InactiveCount   int `json:"inactive_count"`

	EventHooks  []HookSummary `json:"event_hooks,omitempty"`
	InlineHooks []HookSummary `json:"inline_hooks,omitempty"`
}

// HookSummary is a per-hook row (audit+).
type HookSummary struct {
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Status           string   `json:"status"`
	SubscribedEvents []string `json:"subscribed_events,omitempty"`

	// Internal-level fields.
	EndpointHost string `json:"endpoint_host,omitempty"`
	ChannelType  string `json:"channel_type,omitempty"`
}

func (c *Collector) collectHooks(ctx context.Context, level componentsdk.Level) *Hooks {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}
	c.status("Collecting hooks...")

	eventHooks, eventErr := c.client.ListEventHooks(ctx)
	if eventErr != nil {
		c.warnSurface("event hooks", "okta.eventHooks.read", eventErr)
	}
	inlineHooks, inlineErr := c.client.ListInlineHooks(ctx)
	if inlineErr != nil {
		c.warnSurface("inline hooks", "okta.inlineHooks.read", inlineErr)
	}
	if eventErr != nil && inlineErr != nil {
		return nil
	}

	out := &Hooks{
		EventHookCount:  len(eventHooks),
		InlineHookCount: len(inlineHooks),
	}
	for _, h := range eventHooks {
		countHookStatus(out, h.Status)
	}
	for _, h := range inlineHooks {
		countHookStatus(out, h.Status)
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out
	}

	internal := level.AtLeast(componentsdk.LevelInternal)

	out.EventHooks = make([]HookSummary, 0, len(eventHooks))
	for _, h := range eventHooks {
		// Event hooks always carry their subscribed-event list, emitted as []
		// even when empty.
		out.EventHooks = append(out.EventHooks, hookSummary(h.Name, h.Events.Type, h.Status, append([]string{}, h.Events.Items...), h.Channel, internal))
	}

	out.InlineHooks = make([]HookSummary, 0, len(inlineHooks))
	for _, h := range inlineHooks {
		out.InlineHooks = append(out.InlineHooks, hookSummary(h.Name, h.Type, h.Status, nil, h.Channel, internal))
	}

	return out
}

// hookSummary builds an audit-level hook row. At internal level it adds the
// endpoint host (host only, never the full URL) and channel type. The hook's
// auth headers and secrets are never read here.
func hookSummary(name, hookType, status string, subscribedEvents []string, channel okta.HookChannel, internal bool) HookSummary {
	row := HookSummary{
		Name:             name,
		Type:             hookType,
		Status:           status,
		SubscribedEvents: subscribedEvents,
	}
	if internal {
		row.EndpointHost = hostOnly(channel.Config.URI)
		row.ChannelType = channel.Type
	}
	return row
}

func countHookStatus(out *Hooks, status string) {
	if status == StatusActive {
		out.ActiveCount++
	} else {
		out.InactiveCount++
	}
}

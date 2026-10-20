package collector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// systemLogWindow bounds the System Log slice to the last 7 days.
const systemLogWindow = 7 * 24 * time.Hour

// securityRelevantEventTypes maps a category to the Okta event types collected
// for it. The filter query is built as an `eventType eq "X" or ...` chain over
// every type here, which is the only practical way to bound System Log volume
// for busy orgs. Revisit when Okta adds security-relevant event types.
var securityRelevantEventTypes = map[string][]string{
	"user.account": {
		"user.account.lock",
		"user.account.unlock",
		"user.lifecycle.create",
		"user.lifecycle.activate",
		"user.lifecycle.suspend",
		"user.lifecycle.unsuspend",
		"user.lifecycle.delete.initiated",
		"user.account.update_password",
		"user.mfa.factor.activate",
		"user.mfa.factor.deactivate",
		"user.mfa.factor.reset_all",
	},
	"user.session": {
		"user.session.start",
		"user.session.access_admin_app",
	},
	"policy": {
		"policy.lifecycle.create",
		"policy.lifecycle.update",
		"policy.lifecycle.delete",
		"policy.rule.create",
		"policy.rule.update",
		"policy.rule.delete",
	},
	"application": {
		"application.lifecycle.create",
		"application.lifecycle.update",
		"application.lifecycle.delete",
		"application.user_membership.add",
		"application.user_membership.remove",
		"app.oauth2.as.consent.grant",
	},
	"group": {
		"group.lifecycle.create",
		"group.lifecycle.delete",
		"group.user_membership.add",
		"group.user_membership.remove",
	},
	"system": {
		"system.api_token.create",
		"system.api_token.revoke",
	},
	"iam": {
		"user.account.privilege.grant",
		"user.account.privilege.revoke",
		"group.privilege.grant",
		"group.privilege.revoke",
	},
	"security": {
		"security.zone.create",
		"security.zone.update",
		"security.zone.delete",
		"security.threat.detected",
	},
}

// SystemLog is the system-log surface.
//
// Trust: none (omitted).
// Audit: count of security-relevant events in the last 7 days, by category.
// Internal: the event slice (capped at SystemLogCap, newest first). No
// debug-context payloads.
type SystemLog struct {
	WindowDays      int            `json:"window_days"`
	CountByCategory map[string]int `json:"count_by_category"`

	Events        []LogEventRow `json:"events,omitempty"`
	Truncated     bool          `json:"truncated,omitempty"`
	OldestEventID string        `json:"oldest_event_id,omitempty"`
	NewestEventID string        `json:"newest_event_id,omitempty"`
}

// LogEventRow is a single security-relevant event (internal).
type LogEventRow struct {
	EventType  string         `json:"event_type"`
	Published  string         `json:"published"`
	Outcome    string         `json:"outcome,omitempty"`
	ActorLogin string         `json:"actor_login,omitempty"`
	ActorType  string         `json:"actor_type,omitempty"`
	ClientIP   string         `json:"client_ip,omitempty"`
	UserAgent  string         `json:"user_agent,omitempty"`
	Targets    []LogTargetRow `json:"targets,omitempty"`
}

// LogTargetRow is an entity a log event acted on.
type LogTargetRow struct {
	DisplayName string `json:"display_name"`
	Type        string `json:"type"`
}

// buildSystemLogFilter constructs the `eventType eq "X" or ...` SCIM filter over
// every security-relevant event type. The output ordering is deterministic
// (category-sorted, then type order) so tests can assert it.
func buildSystemLogFilter() string {
	categories := make([]string, 0, len(securityRelevantEventTypes))
	for category := range securityRelevantEventTypes {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	clauses := make([]string, 0)
	for _, category := range categories {
		for _, eventType := range securityRelevantEventTypes[category] {
			clauses = append(clauses, fmt.Sprintf("eventType eq %q", eventType))
		}
	}
	return strings.Join(clauses, " or ")
}

// eventTypeCategory reverses securityRelevantEventTypes to look up an event's
// category for the audit-level counts.
func eventTypeCategory(eventType string) string {
	for category, types := range securityRelevantEventTypes {
		for _, t := range types {
			if t == eventType {
				return category
			}
		}
	}
	return "other"
}

func (c *Collector) collectSystemLog(ctx context.Context, level componentsdk.Level) *SystemLog {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	since := c.config.now().Add(-systemLogWindow)
	events, err := c.client.ListSystemLog(ctx, buildSystemLogFilter(), since, SystemLogCap)
	if err != nil {
		err = c.warnSurface("system log", "okta.logs.read", err)
		c.gaps.notCollected(err, "/system_log")
		return nil
	}

	// Newest first.
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Published.After(events[j].Published)
	})

	out := &SystemLog{
		WindowDays:      int(systemLogWindow / (24 * time.Hour)),
		CountByCategory: make(map[string]int),
	}
	for _, e := range events {
		out.CountByCategory[eventTypeCategory(e.EventType)]++
	}

	if !level.AtLeast(componentsdk.LevelInternal) {
		return out
	}

	out.Events = make([]LogEventRow, 0, len(events))
	for _, e := range events {
		out.Events = append(out.Events, logEventRow(e))
	}

	if len(events) >= SystemLogCap {
		out.Truncated = true
		out.NewestEventID = events[0].UUID
		out.OldestEventID = events[len(events)-1].UUID
		c.warn("system log: event slice truncated at %d events (7d window)", SystemLogCap)
	}

	return out
}

// logEventRow projects a System Log event onto its internal row, dropping the
// debug-context payload entirely.
func logEventRow(e okta.LogEvent) LogEventRow {
	row := LogEventRow{
		EventType:  e.EventType,
		Published:  e.Published.UTC().Format(time.RFC3339),
		Outcome:    e.Outcome.Result,
		ActorLogin: e.Actor.AlternateID,
		ActorType:  e.Actor.Type,
		ClientIP:   e.Client.IPAddress,
		UserAgent:  e.Client.UserAgent.RawUserAgent,
	}
	for _, t := range e.Target {
		row.Targets = append(row.Targets, LogTargetRow{DisplayName: t.DisplayName, Type: t.Type})
	}
	return row
}

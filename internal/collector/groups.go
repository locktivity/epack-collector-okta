package collector

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// Groups is the groups surface. It is collected at audit and above; trust omits
// it.
//
// Audit: total count + count by source + per-group inventory.
// Internal: per-group member-login list (capped at GroupMembershipsCap total
// rows across all groups; smallest groups truncated first).
type Groups struct {
	TotalCount    int            `json:"total_count"`
	CountBySource map[string]int `json:"count_by_source"`

	Inventory []GroupSummary `json:"inventory,omitempty"`

	// Internal truncation signal for member-login lists.
	TruncatedMemberships        bool `json:"truncated_memberships,omitempty"`
	TruncatedMembershipsDropped int  `json:"truncated_memberships_dropped,omitempty"`
}

// GroupSummary is a per-group inventory row (audit+). Internal adds member logins.
//
// MemberCount is Okta's group statistics at audit. At internal it counts the
// members read live, so it matches MemberLogins; only a group past the
// membership budget, whose members are not read, keeps the statistics.
type GroupSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Source      string `json:"source"`
	Description string `json:"description,omitempty"`
	MemberCount *int   `json:"member_count"`
	CreatedAt   string `json:"created_at,omitempty"`

	// Internal-level field.
	MemberLogins []string `json:"member_logins,omitempty"`

	countErr   error
	membersErr error
}

// collectGroups collects the groups surface (audit and above). Returns nil at
// trust, or, with a gap, when the group list cannot be fetched.
func (c *Collector) collectGroups(ctx context.Context, level componentsdk.Level) *Groups {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	var groups []okta.Group
	if err := c.client.ListGroups(ctx, func(batch []okta.Group) error {
		groups = append(groups, batch...)
		return nil
	}); err != nil {
		err = c.warnSurface("groups", "okta.groups.read", err)
		c.gaps.notCollected(err, "/groups")
		return nil
	}

	out := &Groups{
		TotalCount:    len(groups),
		CountBySource: make(map[string]int),
	}
	for _, g := range groups {
		out.CountBySource[g.Type]++
	}

	out.Inventory = make([]GroupSummary, 0, len(groups))
	for _, g := range groups {
		row := GroupSummary{
			ID:          g.ID,
			Name:        g.Profile.Name,
			Type:        g.Type,
			Source:      g.Type,
			Description: g.Profile.Description,
		}
		if g.Embedded != nil && g.Embedded.Stats != nil {
			row.MemberCount = intPtr(g.Embedded.Stats.UsersCount)
		} else {
			row.countErr = invalidGroup("has no member statistics")
		}
		row.CreatedAt = formatTime(g.Created)
		out.Inventory = append(out.Inventory, row)
	}

	// Largest groups are the most access-significant: emit member lists in
	// member-count-desc order so the total-row cap drops the smallest groups
	// first.
	sort.SliceStable(out.Inventory, func(i, j int) bool {
		return statsCount(out.Inventory[i]) > statsCount(out.Inventory[j])
	})

	if len(out.Inventory) > GroupsCap {
		dropped := len(out.Inventory) - GroupsCap
		out.Inventory = out.Inventory[:GroupsCap]
		c.warn("groups: inventory truncated to %d (dropped %d)", GroupsCap, dropped)
	}

	if level.AtLeast(componentsdk.LevelInternal) {
		c.fillGroupMemberLoginsWithBudget(ctx, out, GroupMembershipsCap)
	}

	for i, row := range out.Inventory {
		if row.countErr != nil {
			c.gaps.notCollected(row.countErr, rowPointer("/groups/inventory", i, "member_count"))
		}
		if row.membersErr != nil {
			c.gaps.notCollected(row.membersErr, rowPointer("/groups/inventory", i, "member_logins"))
		}
	}

	return out
}

func statsCount(row GroupSummary) int {
	if row.MemberCount == nil {
		return -1
	}
	return *row.MemberCount
}

// fillGroupMemberLoginsWithBudget populates per-group member-login lists for the
// internal level, bounded by maxRows total member-rows across all groups. A
// group's logins are emitted whole or not at all, and its member count is
// the number of members read. Once a group does not fit, it and every smaller
// group are left without logins.
func (c *Collector) fillGroupMemberLoginsWithBudget(ctx context.Context, out *Groups, maxRows int) {
	remaining := maxRows

	for i := range out.Inventory {
		row := &out.Inventory[i]
		if remaining <= 0 {
			out.TruncatedMemberships = true
			if row.MemberCount != nil {
				out.TruncatedMembershipsDropped += *row.MemberCount
			}
			continue
		}

		logins := []string{}
		err := c.client.FetchGroupUsers(ctx, row.ID, func(users []okta.User) error {
			for _, u := range users {
				logins = append(logins, u.Profile.Login)
			}
			return nil
		})
		if err != nil {
			err = c.warnSurface(fmt.Sprintf("group %s: failed to fetch members", row.ID), "okta.groups.read", err)
			row.MemberCount = nil
			row.countErr = err
			row.membersErr = err
			continue
		}

		row.MemberCount = intPtr(len(logins))
		row.countErr = nil
		if len(logins) > remaining {
			out.TruncatedMemberships = true
			out.TruncatedMembershipsDropped += len(logins)
			remaining = 0
			continue
		}
		row.MemberLogins = logins
		remaining -= len(logins)
	}
}

func invalidGroup(problem string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("the group "+problem))
}

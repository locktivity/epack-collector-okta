package collector

import (
	"context"
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
type GroupSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Source      string `json:"source"`
	Description string `json:"description,omitempty"`
	MemberCount int    `json:"member_count"`
	CreatedAt   string `json:"created_at,omitempty"`

	// Internal-level field.
	MemberLogins []string `json:"member_logins,omitempty"`
}

// collectGroups collects the groups surface (audit and above). Returns nil at
// trust, or when the group list cannot be fetched.
func (c *Collector) collectGroups(ctx context.Context, level componentsdk.Level) *Groups {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	c.status("Collecting groups...")

	var groups []okta.Group
	if err := c.client.ListGroups(ctx, func(batch []okta.Group) error {
		groups = append(groups, batch...)
		return nil
	}); err != nil {
		c.warnSurface("groups", "okta.groups.read", err)
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
			row.MemberCount = g.Embedded.Stats.UsersCount
		}
		row.CreatedAt = formatTime(g.Created)
		out.Inventory = append(out.Inventory, row)
	}

	// Largest groups are the most access-significant: emit member lists in
	// member-count-desc order so the total-row cap drops the smallest groups
	// first.
	sort.SliceStable(out.Inventory, func(i, j int) bool {
		return out.Inventory[i].MemberCount > out.Inventory[j].MemberCount
	})

	if len(out.Inventory) > GroupsCap {
		dropped := len(out.Inventory) - GroupsCap
		out.Inventory = out.Inventory[:GroupsCap]
		c.warn("groups: inventory truncated to %d (dropped %d)", GroupsCap, dropped)
	}

	if level.AtLeast(componentsdk.LevelInternal) {
		c.fillGroupMemberLoginsWithBudget(ctx, out, GroupMembershipsCap)
	}

	return out
}

// fillGroupMemberLoginsWithBudget populates per-group member-login lists for the
// internal level, bounded by maxRows total member-rows across all groups.
func (c *Collector) fillGroupMemberLoginsWithBudget(ctx context.Context, out *Groups, maxRows int) {
	remaining := maxRows

	for i := range out.Inventory {
		if remaining <= 0 {
			out.TruncatedMemberships = true
			out.TruncatedMembershipsDropped += out.Inventory[i].MemberCount
			out.Inventory[i].MemberLogins = []string{}
			continue
		}

		logins := []string{}
		err := c.client.FetchGroupUsers(ctx, out.Inventory[i].ID, func(users []okta.User) error {
			for _, u := range users {
				if remaining <= 0 {
					out.TruncatedMemberships = true
					out.TruncatedMembershipsDropped++
					continue
				}
				logins = append(logins, u.Profile.Login)
				remaining--
			}
			return nil
		})
		if err != nil {
			c.warn("group %s: failed to fetch members: %v", out.Inventory[i].ID, err)
		}
		out.Inventory[i].MemberLogins = logins
	}
}

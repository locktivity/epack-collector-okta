package collector

import (
	"context"
	"testing"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

func stats(n int) *okta.GroupEmbedded {
	return &okta.GroupEmbedded{Stats: &struct {
		UsersCount int `json:"usersCount"`
	}{UsersCount: n}}
}

func groupsTestClient() *mockOktaClient {
	return &mockOktaClient{
		users:    []okta.User{},
		factors:  make(map[string][]okta.Factor),
		apps:     []okta.Application{},
		policies: make(map[string][]okta.Policy),
		groups: []okta.Group{
			{ID: "g1", Type: "OKTA_GROUP", Profile: okta.GroupProfile{Name: "Engineers"}, Embedded: stats(2)},
			{ID: "g2", Type: "APP_GROUP", Profile: okta.GroupProfile{Name: "App Group"}, Embedded: stats(1)},
		},
		groupUsers: map[string][]okta.User{
			"g1": {{Profile: okta.UserProfile{Login: "a@acme.com"}}, {Profile: okta.UserProfile{Login: "b@acme.com"}}},
			"g2": {{Profile: okta.UserProfile{Login: "c@acme.com"}}},
		},
	}
}

func TestGroups_OmittedAtTrust(t *testing.T) {
	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, groupsTestClient())
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.Groups != nil {
		t.Errorf("expected groups surface to be omitted at trust, got %+v", posture.Groups)
	}
}

func TestGroups_AuditAndInternal(t *testing.T) {
	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, groupsTestClient())

	audit, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("audit error: %v", err)
	}
	if audit.Groups.TotalCount != 2 {
		t.Errorf("expected 2 groups, got %d", audit.Groups.TotalCount)
	}
	if audit.Groups.CountBySource["OKTA_GROUP"] != 1 || audit.Groups.CountBySource["APP_GROUP"] != 1 {
		t.Errorf("count by source wrong: %v", audit.Groups.CountBySource)
	}
	if len(audit.Groups.Inventory) != 2 {
		t.Fatalf("expected 2 inventory rows at audit, got %d", len(audit.Groups.Inventory))
	}
	// Sorted member-count-desc: Engineers (2) first.
	if audit.Groups.Inventory[0].Name != "Engineers" {
		t.Errorf("expected Engineers first, got %+v", audit.Groups.Inventory[0])
	}
	if audit.Groups.Inventory[0].MemberLogins != nil {
		t.Errorf("expected no member logins at audit, got %v", audit.Groups.Inventory[0].MemberLogins)
	}

	internal, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("internal error: %v", err)
	}
	if len(internal.Groups.Inventory[0].MemberLogins) != 2 {
		t.Errorf("expected 2 member logins for Engineers at internal, got %v", internal.Groups.Inventory[0].MemberLogins)
	}
}

func TestGroups_MembershipCapFires(t *testing.T) {
	c := NewWithClient(Config{OrgDomain: "test.okta.com"}, groupsTestClient())
	out := &Groups{
		Inventory: []GroupSummary{
			{ID: "g1", MemberCount: 2},
			{ID: "g2", MemberCount: 1},
		},
	}
	// Shrink the effective budget by pre-filling: simulate via a tiny cap path.
	// Use the real path but assert truncation bookkeeping by exhausting budget.
	c.fillGroupMemberLoginsWithBudget(context.Background(), out, 2)

	if !out.TruncatedMemberships {
		t.Error("expected truncation flag to fire when budget exceeded")
	}
	if out.TruncatedMembershipsDropped != 1 {
		t.Errorf("expected 1 dropped membership row, got %d", out.TruncatedMembershipsDropped)
	}
}

package collector

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// oktaSim answers the calls the collector makes at the audit level for an
// org a roster describes, as Okta's management API answers them. Each item
// is a copy of one the sandbox's recording holds, the closest kind it has,
// with the fields the roster decides set, so the answers keep Okta's nulls,
// optional fields and envelopes. Okta's Link header paging and its E0000006
// refusal are the kit's, and the scope and admin role each call needs
// follow Okta's API reference, not the collector.
//
// An account's state is its Okta status, which must agree with enabled, an
// app's provisioning is its features, and a sign-in policy's session limits
// are its rule's, with no limit sent as 0. The roster's vendor extras give
// each account's login, user_type, and factors not yet activated
// (pending_factors), the global session policies its sign-in policies are
// rules of (sign_on_policies, each rule's policy and rule), the enrollment
// and password policies, each app's label, name and grant types, whether
// it has an app sign-in policy (access_policy, true unless set false), the
// collector app's scopes and admin roles, the authenticators,
// the network zones, and custom admin roles (custom_roles, by name, with
// their permissions). Group key everyone is Okta's Everyone group.
//
// An account's signs_in_through is a key of the identity_providers extra,
// each a SAML 2.0 provider with a name, and optionally more login domains
// its routing rule sends to it (domains) and a network zone the rule is
// limited to (zone). Okta's IdP routing policy has a rule for each
// provider, ahead of its Default Rule, which sends the account's login
// there, by domain where no account that signs in elsewhere shares it.
// Okta lists none of such an account's factors, which the other provider
// holds. An account's provider extra is its credentials provider, such as
// FEDERATION for one a provider created, and routed false leaves it out of
// the routing rules, which only an account Okta holds no password for can
// do.
type oktaSim struct {
	r        *roster.Roster
	rec      *simulate.Recorded
	now      time.Time
	granted  []string
	pageSize int
	t        *simulate.Tenant
	userIDs  map[string]string
}

// simRecordingPath is the sandbox's recording, which TestRecord writes.
const simRecordingPath = "testdata/recordings/okta.json"

var simRecorded = sync.OnceValues(func() (*simulate.Recorded, error) { return simulate.LoadRecorded(simRecordingPath) })

func simRecording(t testing.TB) *simulate.Recorded {
	t.Helper()
	rec, err := simRecorded()
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// simUsersPage is the page size the collector asks for and Okta honors.
const simUsersPage = 200

// simEnabled are the statuses an enabled account takes.
var simEnabled = []string{StatusActive, StatusPasswordExpired, StatusLockedOut, "RECOVERY"}

func newOktaSim(r *roster.Roster, rec *simulate.Recorded, now time.Time, pageSize int) *oktaSim {
	s := &oktaSim{r: r, rec: rec, now: now, pageSize: pageSize, userIDs: map[string]string{}}
	i := slices.IndexFunc(r.Apps, func(a roster.App) bool { return a.Key == "collector" })
	if i < 0 {
		panic("oktaSim: the roster has no collector app")
	}
	var roles []string
	simulate.Extra(r.Apps[i].Extra, "scopes", &s.granted)
	simulate.Extra(r.Apps[i].Extra, "roles", &roles)
	for _, role := range roles {
		s.granted = append(s.granted, "role:"+role)
	}
	for _, a := range r.Accounts {
		s.userIDs[a.Key] = simulate.Base62("00u", 17, "user", a.Key)
	}
	return s
}

// Any admin role can read the management API. Listing role assignees and
// API tokens takes a Super Administrator.
var (
	simAnyAdmin = []string{"role:SUPER_ADMIN", "role:ORG_ADMIN", "role:READ_ONLY_ADMIN", "role:APP_ADMIN", "role:USER_ADMIN",
		"role:HELP_DESK_ADMIN", "role:REPORT_ADMIN", "role:MOBILE_ADMIN", "role:API_ACCESS_MANAGEMENT_ADMIN", "role:GROUP_MEMBERSHIP_ADMIN"}
	simSuperAdmin = []string{"role:SUPER_ADMIN"}
)

func reads(scope string) simulate.Need { return simulate.Needs([]string{scope}, simAnyAdmin) }

// simRefusal is Okta's answer when the token lacks the call's scope or the
// app's admin role can't make it.
func simRefusal(simulate.Refusal) collectortest.Response {
	return collectortest.Response{Status: http.StatusForbidden, Body: simulate.JSON(map[string]any{
		"errorCode": "E0000006", "errorSummary": "You do not have permission to perform the requested action",
		"errorLink": "E0000006", "errorId": "oae-sim", "errorCauses": []any{},
	})}
}

func (s *oktaSim) responses() []collectortest.Response {
	s.t = &simulate.Tenant{Granted: s.granted, PageSize: s.pageSize, Refuse: simRefusal}
	var scopes []string
	for _, g := range s.granted {
		if !strings.HasPrefix(g, "role:") {
			scopes = append(scopes, g)
		}
	}
	token := s.rec.Body("okta.token.create")
	token["access_token"], token["scope"] = "sim-access-token-0123456789", strings.Join(scopes, " ")
	s.t.Do("okta.token.create", http.MethodPost, kitBase+"/oauth2/v1/token", simulate.Need{}, token)
	s.users()
	s.groups()
	s.roles()
	s.apps()
	s.policies()
	s.routing()
	s.surfaces()
	return s.t.Responses()
}

var simByID = func(item any) string { return item.(map[string]any)["id"].(string) }

func simLinked() simulate.LinkHeader {
	return simulate.LinkHeader{Cursor: "after", Size: simUsersPage, CursorOf: simByID}
}

func (s *oktaSim) at(days int) string {
	return s.now.Add(-time.Duration(days) * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
}

func (s *oktaSim) status(a roster.Account) string {
	status := cmp.Or(a.State, StatusActive)
	if a.State == "" && !a.Enabled {
		status = StatusSuspended
	}
	if slices.Contains(simEnabled, status) != a.Enabled {
		panic(fmt.Sprintf("oktaSim: account %s is %s and enabled %v", a.Key, status, a.Enabled))
	}
	return status
}

// listed are the accounts Okta lists: all but deprovisioned ones.
func (s *oktaSim) listed() []roster.Account {
	return slices.DeleteFunc(slices.Clone(s.r.Accounts), func(a roster.Account) bool { return s.status(a) == StatusDeprovisioned })
}

// user renders an account from a recorded user of the same status, as op
// lists it.
func (s *oktaSim) user(op string, a roster.Account) any {
	status := s.status(a)
	login, userType := strings.ReplaceAll(a.Key, "_", ".")+"@example.com", ""
	simulate.Extra(a.Extra, "login", &login)
	simulate.Extra(a.Extra, "user_type", &userType)
	u := s.rec.Like(op, "", func(m map[string]any) bool { return m["status"] == status })
	id := s.userIDs[a.Key]
	u["id"], u["status"], u["lastLogin"] = id, status, nil
	if a.SignedInDaysAgo != nil {
		u["lastLogin"] = s.now.Add(-time.Duration(*a.SignedInDaysAgo)*24*time.Hour - time.Minute).UTC().Format("2006-01-02T15:04:05.000Z")
		if *a.SignedInDaysAgo > 0 {
			u["lastLogin"] = s.at(*a.SignedInDaysAgo)
		}
	}
	simulate.Set(u, "profile/login", login)
	simulate.Set(u, "profile/email", login)
	simulate.Set(u, "profile/lastName", a.Key)
	simulate.Drop(u, "profile/userType")
	if userType != "" {
		simulate.Set(u, "profile/userType", userType)
	}
	simulate.Set(u, "_links/self/href", kitBase+"/api/v1/users/"+id)
	provider := s.provider(a)
	simulate.Set(u, "credentials/provider", map[string]any{"type": provider, "name": provider})
	if !simPasswordProviders[provider] {
		simulate.Drop(u, "credentials/password")
	}
	return u
}

// simPasswordProviders are the credentials providers that check a password
// Okta holds or delegates. FEDERATION and SOCIAL accounts have none and
// sign in only through an identity provider.
var simPasswordProviders = map[string]bool{"OKTA": true, "ACTIVE_DIRECTORY": true, "LDAP": true, "IMPORT": true}

func (s *oktaSim) provider(a roster.Account) string {
	provider := "OKTA"
	simulate.Extra(a.Extra, "provider", &provider)
	return provider
}

func (s *oktaSim) users() {
	listed := s.listed()
	s.t.List("okta.users.list", kitBase+"/api/v1/users?limit=200", reads("okta.users.read"), simLinked(),
		simulate.Each(listed, func(a roster.Account) any { return s.user("okta.users.list", a) }))
	for _, a := range listed {
		id := s.userIDs[a.Key]
		var pending []string
		simulate.Extra(a.Extra, "pending_factors", &pending)
		methods := a.Methods
		if a.SignsInThrough != "" {
			methods = nil
		}
		var factors []any
		for i, method := range append(slices.Clone(methods), pending...) {
			f := s.rec.Like("okta.users.factors.list", "", func(m map[string]any) bool { return m["factorType"] == method })
			f["id"], f["factorType"], f["status"] = simulate.Base62("fct", 17, "factor", a.Key+method), method, "ACTIVE"
			if i >= len(methods) {
				f["status"] = "PENDING_ACTIVATION"
			}
			factors = append(factors, f)
		}
		s.t.Get("okta.users.factors.list", kitBase+"/api/v1/users/"+id+"/factors?", reads("okta.users.read"), nonNil(factors))
	}
}

// simGroup is a group as Okta lists it: Okta's two built-in groups, then
// the roster's.
type simGroup struct {
	key, name, kind string
	members, roles  []string
}

func (s *oktaSim) allGroups() []simGroup {
	var everyone []string
	for _, a := range s.listed() {
		everyone = append(everyone, a.Key)
	}
	out := []simGroup{{key: "everyone", name: "Everyone", kind: GroupTypeBuiltIn, members: everyone}, {key: "administrators", name: "Okta Administrators", kind: GroupTypeBuiltIn}}
	for _, g := range s.r.Groups {
		name := g.Key
		simulate.Extra(g.Extra, "name", &name)
		members := slices.DeleteFunc(slices.Clone(g.Members), func(k string) bool { a, _ := s.r.Account(k); return s.status(a) == StatusDeprovisioned })
		out = append(out, simGroup{key: g.Key, name: name, kind: "OKTA_GROUP", members: members, roles: g.Roles})
	}
	return out
}

func simGroupID(key string) string { return simulate.Base62("00g", 17, "group", key) }

func (s *oktaSim) groups() {
	all := s.allGroups()
	render := func(g simGroup) any {
		item := s.rec.Like("okta.groups.list", "", func(m map[string]any) bool { return m["type"] == g.kind })
		id := simGroupID(g.key)
		item["id"] = id
		simulate.Set(item, "profile/name", g.name)
		simulate.Set(item, "profile/description", g.name)
		simulate.Set(item, "_embedded/stats/usersCount", len(g.members))
		simulate.Set(item, "_embedded/stats/hasAdminPrivilege", len(g.roles) > 0)
		simulate.Set(item, "_links/users/href", kitBase+"/api/v1/groups/"+id+"/users")
		return item
	}
	s.t.List("okta.groups.list", kitBase+"/api/v1/groups?expand=stats&limit=200", reads("okta.groups.read"), simLinked(), simulate.Each(all, render))
	for _, g := range all {
		var members []any
		for _, key := range g.members {
			a, _ := s.r.Account(key)
			members = append(members, s.user("okta.groups.users.list", a))
		}
		s.t.List("okta.groups.users.list", kitBase+"/api/v1/groups/"+simGroupID(g.key)+"/users?limit=200", reads("okta.groups.read"), simLinked(), members)
	}
}

// simRoleLabels are the labels Okta gives its built-in admin roles.
var simRoleLabels = map[string]string{
	"SUPER_ADMIN": "Super Administrator", "ORG_ADMIN": "Organization Administrator", "APP_ADMIN": "Application Administrator",
	"USER_ADMIN": "Group Administrator", "HELP_DESK_ADMIN": "Help Desk Administrator", "READ_ONLY_ADMIN": "Read-only Administrator",
	"MOBILE_ADMIN": "Mobile Administrator", "API_ACCESS_MANAGEMENT_ADMIN": "API Access Management Administrator",
	"REPORT_ADMIN": "Report Administrator", "GROUP_MEMBERSHIP_ADMIN": "Group Membership Administrator",
}

// roles lists the users who hold an admin role, directly or through a
// group, and each one's assignments, with the custom roles. Okta lists a
// suspended admin too.
func (s *oktaSim) roles() {
	var custom map[string]struct {
		Permissions []string `json:"permissions"`
	}
	simulate.Extra(s.r.Extra, "custom_roles", &custom)
	assignment := func(role, kind, assignee, href string) any {
		item := s.rec.Like("okta.users.roles.list", "", func(m map[string]any) bool { return m["assignmentType"] == kind })
		item["id"], item["type"], item["label"], item["assignmentType"] = simulate.Base62("ra1", 17, "assignment", assignee+role), role, simRoleLabels[role], kind
		if _, ok := custom[role]; ok {
			item["type"], item["label"], item["role"] = "CUSTOM", role, simulate.Base62("cr0", 17, "role", role)
		}
		simulate.Set(item, "_links/assignee/href", href)
		return item
	}
	var assignees []any
	for _, a := range s.listed() {
		id := s.userIDs[a.Key]
		var held []any
		for _, role := range a.Roles {
			held = append(held, assignment(role, "USER", id, kitBase+"/api/v1/users/"+id))
		}
		for _, g := range s.r.Groups {
			if slices.Contains(g.Members, a.Key) {
				for _, role := range g.Roles {
					held = append(held, assignment(role, "GROUP", simGroupID(g.Key), kitBase+"/api/v1/groups/"+simGroupID(g.Key)))
				}
			}
		}
		if len(held) == 0 {
			continue
		}
		item := s.rec.Like("okta.iam.assignees.list", "value")
		item["id"], item["orn"] = id, "orn:okta:directory:sim:users:"+id
		simulate.Set(item, "_links/roles/href", kitBase+"/api/v1/users/"+id+"/roles")
		simulate.Set(item, "_links/self/href", kitBase+"/api/v1/users/"+id)
		assignees = append(assignees, item)
		s.t.Get("okta.users.roles.list", kitBase+"/api/v1/users/"+id+"/roles?", reads("okta.roles.read"), held)
	}
	s.t.List("okta.iam.assignees.list", kitBase+"/api/v1/iam/assignees/users?limit=200", simulate.Needs([]string{"okta.roles.read"}, simSuperAdmin),
		simulate.NextLink{Items: "value", Next: "_links/next/href", Token: "after", Size: simUsersPage, Envelope: s.envelope("okta.iam.assignees.list", "value")}, assignees)

	// Okta lists its Workflows Administrator role with the custom roles.
	iamRoles := []any{s.rec.Like("okta.iam.roles.list", "roles", func(m map[string]any) bool { return m["id"] == workflowsAdminRole })}
	for _, name := range slices.Sorted(maps.Keys(custom)) {
		id := simulate.Base62("cr0", 17, "role", name)
		item := s.rec.Like("okta.iam.roles.list", "roles")
		item["id"], item["label"], item["description"] = id, name, name
		iamRoles = append(iamRoles, item)
		var permissions []any
		for _, p := range custom[name].Permissions {
			permissions = append(permissions, map[string]any{"label": p})
		}
		s.t.Get("okta.iam.roles.permissions.list", kitBase+"/api/v1/iam/roles/"+id+"/permissions", reads("okta.roles.read"), map[string]any{"permissions": nonNil(permissions)})
	}
	s.t.List("okta.iam.roles.list", kitBase+"/api/v1/iam/roles?limit=200", reads("okta.roles.read"),
		simulate.NextLink{Items: "roles", Next: "_links/next/href", Token: "after", Size: simUsersPage, Envelope: s.envelope("okta.iam.roles.list", "roles")}, iamRoles)
}

// envelope is a recorded answer to op without the items in field.
func (s *oktaSim) envelope(op, field string) map[string]any {
	body := s.rec.Body(op)
	delete(body, field)
	return body
}

func (s *oktaSim) apps() {
	render := func(a roster.App) any {
		label, name, accessPolicy := a.Key, a.Key, true
		var grants []string
		for field, v := range map[string]any{"label": &label, "name": &name, "grant_types": &grants, "access_policy": &accessPolicy} {
			simulate.Extra(a.Extra, field, v)
		}
		item := s.rec.Like("okta.apps.list", "", func(m map[string]any) bool {
			return m["name"] == name && m["signOnMode"] == a.SSOMode && simServiceApp(m) == (len(grants) > 0)
		}, func(m map[string]any) bool {
			return m["signOnMode"] == a.SSOMode && simServiceApp(m) == (len(grants) > 0)
		})
		id := simulate.Base62("0oa", 17, "app", a.Key)
		item["id"], item["label"], item["name"], item["signOnMode"], item["features"], item["status"] = id, label, name, a.SSOMode, nonNil(a.Provisioning), "ACTIVE"
		if !a.Enabled {
			item["status"] = AppStatusInactive
		}
		if len(grants) > 0 {
			simulate.Set(item, "settings/oauthClient/grant_types", grants)
		}
		simulate.Set(item, "_links/users/href", kitBase+"/api/v1/apps/"+id+"/users")
		simulate.Set(item, "_links/accessPolicy/href", kitBase+"/api/v1/policies/"+simulate.Base62("rst", 17, "access", a.Key))
		if !accessPolicy {
			simulate.Drop(item, "_links/accessPolicy")
		}
		return item
	}
	s.t.List("okta.apps.list", kitBase+"/api/v1/apps?limit=200", reads("okta.apps.read"), simLinked(), simulate.Each(s.r.Apps, render))
}

// simServiceApp reports whether a recorded app is an API service app, one
// whose only grant is client_credentials.
func simServiceApp(app map[string]any) bool {
	settings, _ := app["settings"].(map[string]any)
	client, _ := settings["oauthClient"].(map[string]any)
	grants, _ := client["grant_types"].([]any)
	return len(grants) > 0 && !slices.ContainsFunc(grants, func(g any) bool { return g != "client_credentials" })
}

// simPolicy is one of the policy extras: a sign-on policy's, an enrollment
// policy's, or a password policy's.
type simPolicy struct {
	Name     string   `json:"name"`
	Priority int      `json:"priority"`
	System   bool     `json:"system"`
	Groups   []string `json:"groups"`
	// Authenticators gives an enrollment policy's setting for each.
	Authenticators map[string]string `json:"authenticators"`
	Rules          map[string]struct {
		Name     string `json:"name"`
		Priority int    `json:"priority"`
		System   bool   `json:"system"`
		Enroll   string `json:"enroll"`
		Reset    string `json:"reset"`
		Unlock   string `json:"unlock"`
	} `json:"rules"`
}

// simRule is the rule extra of a sign-in policy.
type simRule struct {
	Name          string `json:"name"`
	Priority      int    `json:"priority"`
	System        bool   `json:"system"`
	Prompt        string `json:"prompt"`
	PrimaryFactor string `json:"primary_factor"`
}

// simConditions sets the fields of a sign-on rule's conditions each
// roster condition takes. A condition the map lacks has no Okta rendering.
var simConditions = map[string]func(map[string]any){
	"on_network":     func(c map[string]any) { simulate.Set(c, "network/connection", "ON_NETWORK") },
	"off_network":    func(c map[string]any) { simulate.Set(c, "network/connection", "OFF_NETWORK") },
	"risk_high":      func(c map[string]any) { simulate.Set(c, "riskScore/level", "HIGH") },
	"radius":         func(c map[string]any) { simulate.Set(c, "authContext/authType", "RADIUS") },
	"managed_device": func(c map[string]any) { c["device"] = map[string]any{"managed": true, "registered": true} },
}

func (s *oktaSim) groupIDs(keys []string) []string {
	out := []string{}
	for _, k := range keys {
		out = append(out, simGroupID(k))
	}
	return out
}

// policy renders a policy from a recorded one of its type, a system policy
// from a system one.
func (s *oktaSim) policy(kind, key string, p simPolicy, people []string) map[string]any {
	item := s.rec.Like("okta.policies.list", "", func(m map[string]any) bool { return m["type"] == kind && m["system"] == p.System })
	id := simulate.Base62("00p", 17, "policy", kind+"/"+key)
	item["id"], item["name"], item["priority"], item["system"], item["status"] = id, p.Name, p.Priority, p.System, "ACTIVE"
	simulate.Set(item, "conditions/people/groups/include", s.groupIDs(people))
	simulate.Set(item, "_links/rules/href", kitBase+"/api/v1/policies/"+id+"/rules")
	if kind == PolicyTypeMFAEnroll {
		// Each authenticator's entry copies a recorded one, which can hold
		// constraints, such as WebAuthn's.
		recorded := map[string]map[string]any{}
		for _, policy := range s.rec.Items("okta.policies.list", "") {
			settings, _ := policy["settings"].(map[string]any)
			entries, _ := settings["authenticators"].([]any)
			for _, e := range entries {
				if entry, ok := e.(map[string]any); ok {
					recorded[fmt.Sprint(entry["key"])] = entry
				}
			}
		}
		var authenticators []any
		for _, k := range slices.Sorted(maps.Keys(p.Authenticators)) {
			entry := map[string]any{"key": k}
			if e, ok := recorded[k]; ok {
				entry = maps.Clone(e)
			}
			entry["enroll"] = map[string]any{"self": p.Authenticators[k]}
			authenticators = append(authenticators, entry)
		}
		simulate.Set(item, "settings/authenticators", nonNil(authenticators))
	}
	return item
}

// rule renders a rule of policy from a recorded rule of the same policy
// type, a system rule from a system one.
func (s *oktaSim) rule(policy map[string]any, key, name, status string, priority int, system bool) map[string]any {
	kind := policy["type"].(string)
	item := s.rec.Like("okta.policies.rules.list", "", func(m map[string]any) bool {
		_, signon := m["actions"].(map[string]any)["signon"]
		_, enroll := m["actions"].(map[string]any)["enroll"]
		matches := (kind == PolicyTypeSignOn && signon) || (kind == PolicyTypeMFAEnroll && enroll) || (kind == PolicyTypePassword && !signon && !enroll)
		return matches && m["system"] == system
	})
	item["id"], item["name"], item["status"], item["priority"] = simulate.Base62("0pr", 17, "rule", kind+key), name, status, priority
	simulate.Set(item, "_links/self/href", kitBase+"/api/v1/policies/"+policy["id"].(string)+"/rules/"+item["id"].(string))
	return item
}

// policies answers the three policy lists the collector reads, and each
// policy's rules. A sign-on policy's people are its rules' include, which
// all of them must share, as Okta sets people on the policy.
func (s *oktaSim) policies() {
	var signOn, enroll, password map[string]simPolicy
	simulate.Extra(s.r.Extra, "sign_on_policies", &signOn)
	simulate.Extra(s.r.Extra, "enrollment_policies", &enroll)
	simulate.Extra(s.r.Extra, "password_policies", &password)
	audience := func(a roster.Audience) []string {
		if a.All {
			return []string{"everyone"}
		}
		if len(a.Accounts)+len(a.Roles) > 0 {
			panic("oktaSim: an Okta policy includes groups only")
		}
		return a.Groups
	}
	// A roster extra render holding policies_reversed lists each type's
	// policies from the last priority, which Okta doesn't promise not to.
	var renderings []string
	simulate.Extra(s.r.Extra, "render", &renderings)
	byPriority := func(m map[string]simPolicy) []string {
		keys := slices.SortedFunc(maps.Keys(m), func(a, b string) int { return m[a].Priority - m[b].Priority })
		if slices.Contains(renderings, "policies_reversed") {
			slices.Reverse(keys)
		}
		return keys
	}

	rulesOf := map[string][]roster.Policy{}
	for _, p := range s.r.Policies {
		var key string
		simulate.Extra(p.Extra, "policy", &key)
		rulesOf[key] = append(rulesOf[key], p)
	}
	var signOnList []any
	for _, key := range byPriority(signOn) {
		rules := rulesOf[key]
		if len(rules) == 0 {
			panic("oktaSim: sign-on policy " + key + " has no rules")
		}
		people := audience(rules[0].Include)
		for _, r := range rules[1:] {
			if !slices.Equal(audience(r.Include), people) {
				panic("oktaSim: the rules of sign-on policy " + key + " include different groups")
			}
		}
		policy := s.policy(PolicyTypeSignOn, key, signOn[key], people)
		signOnList = append(signOnList, policy)
		s.t.Get("okta.policies.rules.list", kitBase+"/api/v1/policies/"+policy["id"].(string)+"/rules?", reads("okta.policies.read"),
			simulate.Each(rules, func(r roster.Policy) any { return s.signOnRule(policy, r) }))
	}
	s.t.List("okta.policies.list", kitBase+"/api/v1/policies?type="+PolicyTypeSignOn, reads("okta.policies.read"), simulate.LinkHeader{}, signOnList)

	for kind, policies := range map[string]map[string]simPolicy{PolicyTypeMFAEnroll: enroll, PolicyTypePassword: password} {
		var list []any
		for _, key := range byPriority(policies) {
			p := policies[key]
			policy := s.policy(kind, key, p, p.Groups)
			list = append(list, policy)
			var rules []any
			for ruleKey, r := range p.Rules {
				rule := s.rule(policy, key+ruleKey, r.Name, "ACTIVE", r.Priority, r.System)
				if kind == PolicyTypeMFAEnroll {
					simulate.Set(rule, "actions/enroll/self", r.Enroll)
				} else {
					simulate.Set(rule, "actions/selfServicePasswordReset/access", r.Reset)
					simulate.Set(rule, "actions/selfServiceUnlock/access", r.Unlock)
				}
				rules = append(rules, rule)
			}
			s.t.Get("okta.policies.rules.list", kitBase+"/api/v1/policies/"+policy["id"].(string)+"/rules?", reads("okta.policies.read"), nonNil(rules))
		}
		s.t.List("okta.policies.list", kitBase+"/api/v1/policies?type="+kind, reads("okta.policies.read"), simulate.LinkHeader{}, list)
	}
}

// signOnRule renders a sign-in policy as a global session policy rule. A
// rule extra render holding bare leaves out the conditions Okta's own
// Default Rule leaves out.
func (s *oktaSim) signOnRule(policy map[string]any, p roster.Policy) any {
	var r simRule
	simulate.Extra(p.Extra, "rule", &r)
	var renderings []string
	simulate.Extra(p.Extra, "render", &renderings)
	rule := s.rule(policy, p.Key, cmp.Or(r.Name, p.Key), p.State, r.Priority, r.System)
	conditions := rule["conditions"].(map[string]any)
	users := []string{}
	for _, k := range p.Exclude.Accounts {
		users = append(users, s.userIDs[k])
	}
	simulate.Set(conditions, "people/users/exclude", users)
	if len(p.Exclude.Groups) > 0 {
		simulate.Set(conditions, "people/groups/exclude", s.groupIDs(p.Exclude.Groups))
	}
	if slices.Contains(renderings, "bare") {
		for _, c := range []string{"risk", "riskScore", "identityProvider"} {
			delete(conditions, c)
		}
	}
	for _, c := range p.Conditions {
		render, ok := simConditions[c]
		if !ok {
			panic("oktaSim: no rendering for condition " + c)
		}
		render(conditions)
	}
	requireFactor := slices.ContainsFunc(p.Requires, func(req string) bool { return s.r.Terms.Requirements[req] == roster.RequiresMFA })
	signon := rule["actions"].(map[string]any)["signon"].(map[string]any)
	signon["access"], signon["requireFactor"], signon["primaryFactor"] = AccessAllow, requireFactor, cmp.Or(r.PrimaryFactor, "PASSWORD_IDP")
	if s.r.Terms.Blocks[p.Blocks] == roster.BlocksAll {
		signon["access"], signon["requireFactor"] = AccessDeny, false
	}
	delete(signon, "factorPromptMode")
	if signon["requireFactor"] == true {
		signon["factorPromptMode"] = cmp.Or(r.Prompt, "ALWAYS")
	}
	simulate.Set(signon, "session/maxSessionIdleMinutes", *cmp.Or(p.IdleTimeoutMinutes, new(0)))
	simulate.Set(signon, "session/maxSessionLifetimeMinutes", *cmp.Or(p.SessionLifetimeMinutes, new(0)))
	return rule
}

// simIdP is an identity_providers extra.
type simIdP struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Zone    string   `json:"zone"`
}

func simIdPID(key string) string { return simulate.Base62("0oa", 17, "idp", key) }

// routing answers the identity providers and the IdP routing policy, which
// every org has. Neither is in the recording, whose org has no identity
// provider, so their items follow Okta's API reference and its examples.
func (s *oktaSim) routing() {
	var idps map[string]simIdP
	simulate.Extra(s.r.Extra, "identity_providers", &idps)
	routed := map[string][]roster.Account{}
	for _, a := range s.listed() {
		route := a.SignsInThrough != ""
		simulate.Extra(a.Extra, "routed", &route)
		switch {
		case a.SignsInThrough == "" && route:
			panic("oktaSim: account " + a.Key + " is routed and signs in through no identity provider")
		case a.SignsInThrough == "" && !simPasswordProviders[s.provider(a)]:
			panic("oktaSim: account " + a.Key + " has no password and signs in through no identity provider")
		case a.SignsInThrough != "" && !route && simPasswordProviders[s.provider(a)]:
			panic("oktaSim: account " + a.Key + " signs in through " + a.SignsInThrough + " with no routing rule, and has a password")
		}
		if _, ok := idps[a.SignsInThrough]; a.SignsInThrough != "" && !ok {
			panic("oktaSim: account " + a.Key + " signs in through " + a.SignsInThrough + ", which is no identity provider")
		}
		if route {
			routed[a.SignsInThrough] = append(routed[a.SignsInThrough], a)
		}
	}
	keys := slices.Sorted(maps.Keys(idps))

	var list []any
	for _, key := range keys {
		idp, id := idps[key], simIdPID(key)
		list = append(list, map[string]any{
			"id": id, "type": "SAML2", "name": cmp.Or(idp.Name, key), "status": "ACTIVE",
			"created": s.at(400), "lastUpdated": s.at(400),
			"protocol": map[string]any{
				"type": "SAML2",
				"endpoints": map[string]any{
					"sso": map[string]any{"url": "https://" + key + ".example/sso", "binding": "HTTP-POST", "destination": "https://" + key + ".example/sso"},
					"acs": map[string]any{"binding": "HTTP-POST", "type": "INSTANCE"},
				},
				"credentials": map[string]any{"trust": map[string]any{"issuer": "https://" + key + ".example", "audience": "https://www.okta.com/saml2/service-provider/sim", "kid": simulate.UUID("kid", key)}},
			},
			"policy": map[string]any{
				"provisioning": map[string]any{"action": "AUTO", "profileMaster": true, "groups": map[string]any{"action": "NONE"},
					"conditions": map[string]any{"deprovisioned": map[string]any{"action": "NONE"}, "suspended": map[string]any{"action": "NONE"}}},
				"accountLink":  map[string]any{"filter": nil, "action": "AUTO"},
				"subject":      map[string]any{"userNameTemplate": map[string]any{"template": "idpuser.subjectNameId"}, "filter": "", "matchType": "USERNAME"},
				"mapAMRClaims": false, "maxClockSkew": 0,
			},
			"_links": map[string]any{"users": map[string]any{"href": kitBase + "/api/v1/idps/" + id + "/users"}},
		})
	}
	s.t.List("okta.idps.list", kitBase+"/api/v1/idps?limit=200", reads("okta.idps.read"), simLinked(), list)

	policy := s.rec.Like("okta.policies.list", "", func(m map[string]any) bool { return m["system"] == true })
	id := simulate.Base62("00p", 17, "policy", "IDP_DISCOVERY")
	policy["id"], policy["type"], policy["name"], policy["description"] = id, "IDP_DISCOVERY", "Idp Discovery Policy", "Idp Discovery Policy"
	policy["priority"], policy["status"], policy["conditions"] = 1, "ACTIVE", nil
	delete(policy, "settings")
	simulate.Set(policy, "_links/rules/href", kitBase+"/api/v1/policies/"+id+"/rules")
	s.t.List("okta.policies.list", kitBase+"/api/v1/policies?type=IDP_DISCOVERY", reads("okta.policies.read"), simulate.LinkHeader{}, []any{policy})

	var zones map[string]struct{ Name string }
	simulate.Extra(s.r.Extra, "network_zones", &zones)
	rule := func(key, name string, priority int, system bool, conditions map[string]any, providers []any) any {
		ruleID := simulate.Base62("0pr", 17, "rule", "IDP_DISCOVERY"+key)
		return map[string]any{
			"id": ruleID, "status": "ACTIVE", "name": name, "priority": priority, "system": system, "type": "IDP_DISCOVERY",
			"created": s.at(400), "lastUpdated": s.at(400), "conditions": conditions,
			"actions": map[string]any{"idp": map[string]any{"providers": providers, "idpSelectionType": "SPECIFIC"}},
			"_links": map[string]any{"self": map[string]any{"href": kitBase + "/api/v1/policies/" + id + "/rules/" + ruleID,
				"hints": map[string]any{"allow": []string{"GET", "PUT", "DELETE"}}}},
		}
	}
	var rules []any
	for _, key := range keys {
		idp := idps[key]
		patterns := s.patterns(key, routed[key], idp.Domains)
		if len(patterns) == 0 {
			continue
		}
		network := map[string]any{"connection": "ANYWHERE"}
		if idp.Zone != "" {
			if _, ok := zones[idp.Zone]; !ok {
				panic("oktaSim: identity provider " + key + " is limited to " + idp.Zone + ", which is no network zone")
			}
			network = map[string]any{"connection": "ZONE", "include": []string{simulate.Base62("nzo", 17, "zone", idp.Zone)}}
		}
		conditions := map[string]any{"network": network, "userIdentifier": map[string]any{"type": "IDENTIFIER", "patterns": patterns}}
		rules = append(rules, rule(key, "Route to "+cmp.Or(idp.Name, key), len(rules)+1, false, conditions, []any{map[string]any{"type": "SAML2", "id": simIdPID(key)}}))
	}
	rules = append(rules, rule("default", "Default Rule", len(rules)+1, true, map[string]any{"network": map[string]any{"connection": "ANYWHERE"}}, []any{map[string]any{"type": "OKTA"}}))
	s.t.Get("okta.policies.rules.list", kitBase+"/api/v1/policies/"+id+"/rules?", reads("okta.policies.read"), rules)
}

// patterns are a routing rule's user identifier patterns for the accounts
// it routes and the domains it adds: a domain suffix where every listed
// account with a login there is routed to the same provider, and the login
// otherwise.
func (s *oktaSim) patterns(key string, routed []roster.Account, domains []string) []any {
	loginOf := func(a roster.Account) string {
		login := strings.ReplaceAll(a.Key, "_", ".") + "@example.com"
		simulate.Extra(a.Extra, "login", &login)
		return strings.ToLower(login)
	}
	domainOf := func(login string) string { return login[strings.LastIndex(login, "@")+1:] }
	sameDomain := func(domain string) bool {
		return !slices.ContainsFunc(s.listed(), func(a roster.Account) bool {
			return domainOf(loginOf(a)) == domain && (a.SignsInThrough != key || !slices.ContainsFunc(routed, func(r roster.Account) bool { return r.Key == a.Key }))
		})
	}
	var out []any
	seen := map[string]bool{}
	for _, d := range domains {
		if !sameDomain(d) {
			panic("oktaSim: the routing rule for " + key + " sends " + d + ", where an account signs in elsewhere")
		}
		out = append(out, map[string]any{"matchType": "SUFFIX", "value": d})
		seen[d] = true
	}
	for _, a := range routed {
		login := loginOf(a)
		switch d := domainOf(login); {
		case seen[d]:
		case sameDomain(d):
			out = append(out, map[string]any{"matchType": "SUFFIX", "value": d})
			seen[d] = true
		default:
			out = append(out, map[string]any{"matchType": "EQUALS", "value": login})
		}
	}
	return nonNil(out)
}

// surfaces answers the reads no normalized value comes from: device
// assurance, authenticators, zones, identity providers, API tokens, hooks,
// the System Log, and the org.
func (s *oktaSim) surfaces() {
	var authenticators map[string]struct{ Type, Name, Status string }
	simulate.Extra(s.r.Extra, "authenticators", &authenticators)
	var auths []any
	for _, key := range slices.Sorted(maps.Keys(authenticators)) {
		a := authenticators[key]
		item := s.rec.Like("okta.authenticators.list", "", func(m map[string]any) bool { return m["key"] == key })
		item["key"], item["type"], item["name"], item["status"] = key, a.Type, a.Name, a.Status
		auths = append(auths, item)
	}
	var zones map[string]struct {
		Name, Usage       string
		Gateways, Proxies []string
	}
	simulate.Extra(s.r.Extra, "network_zones", &zones)
	cidrs := func(values []string) any {
		if len(values) == 0 {
			return nil
		}
		var out []any
		for _, v := range values {
			out = append(out, map[string]any{"type": "CIDR", "value": v})
		}
		return out
	}
	// Okta's own zones are in every org, as the recording holds them.
	zoneList := simulate.Each(s.rec.Items("okta.zones.list", ""), func(z map[string]any) any { return z })
	zoneList = slices.DeleteFunc(zoneList, func(z any) bool { return z.(map[string]any)["system"] != true })
	for _, key := range slices.Sorted(maps.Keys(zones)) {
		z := zones[key]
		item := s.rec.Like("okta.zones.list", "", func(m map[string]any) bool { return m["type"] == "IP" && m["system"] == false })
		item["id"], item["name"], item["usage"], item["gateways"], item["proxies"] = simulate.Base62("nzo", 17, "zone", key), z.Name, z.Usage, cidrs(z.Gateways), cidrs(z.Proxies)
		zoneList = append(zoneList, item)
	}
	s.t.Get("okta.device_assurances.list", kitBase+"/api/v1/device-assurances?", reads("okta.deviceAssurance.read"), []any{})
	s.t.Get("okta.authenticators.list", kitBase+"/api/v1/authenticators?", reads("okta.authenticators.read"), nonNil(auths))
	s.t.List("okta.zones.list", kitBase+"/api/v1/zones?limit=200", reads("okta.networkZones.read"), simLinked(), zoneList)
	s.t.Get("okta.api_tokens.list", kitBase+"/api/v1/api-tokens?", simulate.Needs([]string{"okta.apiTokens.read"}, simSuperAdmin), []any{})
	s.t.Get("okta.event_hooks.list", kitBase+"/api/v1/eventHooks?", reads("okta.eventHooks.read"), []any{})
	s.t.Get("okta.inline_hooks.list", kitBase+"/api/v1/inlineHooks?", reads("okta.inlineHooks.read"), []any{})

	q := url.Values{}
	q.Set("since", s.now.Add(-systemLogWindow).Format(time.RFC3339))
	q.Set("sortOrder", "DESCENDING")
	q.Set("limit", "200")
	q.Set("filter", buildSystemLogFilter())
	s.t.Get("okta.logs.list", kitBase+"/api/v1/logs?"+q.Encode(), reads("okta.logs.read"), []any{})

	org := s.rec.Body("okta.org.get")
	org["companyName"], org["subdomain"], org["status"] = "Example", "acme", "ACTIVE"
	s.t.Get("okta.org.get", kitBase+"/api/v1/org?", reads("okta.orgs.read"), org)
}

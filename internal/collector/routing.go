package collector

import (
	"cmp"
	"context"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// signInElsewhere names the identity providers other than Okta that enabled
// users, and admins among them, sign in through. That provider decides
// whether they use MFA. err is why the IdP routing rules could not be read,
// which leaves who signs in elsewhere unknown.
type signInElsewhere struct {
	users, admins []string
	err           error
}

// oktaRoutes are the routing rule provider types that leave the sign-in to
// Okta: Okta itself, its desktop single sign-on, and the smart card
// provider, whose certificates Okta checks.
var oktaRoutes = []string{"OKTA", "IWA", "AgentlessDSSO", "X509"}

// dynamicRoute names the provider of a rule that picks one by expression.
const dynamicRoute = "the identity provider a routing rule's expression picks"

// collectSignInElsewhere reads the IdP routing rules and finds the enabled
// users they can send to another identity provider, and those Okta holds no
// password for, who sign in only through one. When anyone does, an audit or
// internal run reads the identity providers for their names, which only
// those levels show in a gap's detail and request the scope for.
func (c *Collector) collectSignInElsewhere(ctx context.Context, users *userMetricsCollector, privileged *privilegedMetricsCollector, level componentsdk.Level) signInElsewhere {
	if users.err != nil {
		return signInElsewhere{}
	}
	policies, err := c.fetchActivePoliciesWithRules(ctx, PolicyTypeIdPDiscovery)
	if err != nil {
		return signInElsewhere{err: c.warnSurface("IdP routing rules", "okta.policies.read", err)}
	}
	var r routing
	for _, p := range policies {
		for _, rule := range p.rules {
			if rule.Status != "INACTIVE" {
				r.rules = append(r.rules, rule)
			}
		}
	}
	enabled := users.enabled()
	if !slices.ContainsFunc(r.rules, func(rule okta.PolicyRule) bool { return len(r.routedTo(rule)) > 0 }) &&
		!slices.ContainsFunc(enabled, func(u okta.User) bool { return !holdsPassword(u) }) {
		return signInElsewhere{}
	}
	if level.AtLeast(componentsdk.LevelAudit) {
		r.idps, _ = c.client.ListIdentityProviders(ctx)
	}
	found, admins := map[string]bool{}, map[string]bool{}
	for _, u := range enabled {
		for _, name := range r.elsewhere(u) {
			found[name] = true
			if _, ok := privileged.privilegedUserIDs[u.ID]; ok {
				admins[name] = true
			}
		}
	}
	return signInElsewhere{users: slices.Sorted(maps.Keys(found)), admins: slices.Sorted(maps.Keys(admins))}
}

// routing is the org's active IdP routing rules, in the order Okta applies
// them, and its identity providers, which name the rules' providers.
type routing struct {
	rules []okta.PolicyRule
	idps  []okta.IdentityProvider
}

// elsewhere names the identity providers other than Okta that u signs in
// through. Okta applies the first rule whose conditions a sign-in meets. A
// rule that matches u and names no network, platform or app decides every
// sign-in of u's it sees, and one that names some decides only those, so
// the walk goes on. A user Okta holds no password for, such as one an
// identity provider created, signs in through one even when no rule names
// it, and every active one is named.
func (r routing) elsewhere(u okta.User) []string {
	var names []string
	for _, rule := range r.rules {
		if !matchesUser(rule.Conditions.UserIdentifier, u) {
			continue
		}
		names = append(names, r.routedTo(rule)...)
		if !limitsSignIns(rule.Conditions) {
			break
		}
	}
	if len(names) == 0 && !holdsPassword(u) {
		for _, idp := range r.idps {
			if idp.Status != "INACTIVE" {
				names = append(names, cmp.Or(idp.Name, "a "+idp.Type+" identity provider"))
			}
		}
		if len(names) == 0 {
			names = []string{"an identity provider"}
		}
	}
	return names
}

// routedTo names the providers other than Okta a rule sends sign-ins to.
func (r routing) routedTo(rule okta.PolicyRule) []string {
	idp := rule.Actions.IDP
	if idp == nil {
		return nil
	}
	if idp.IdpSelectionType == "DYNAMIC" {
		return []string{dynamicRoute}
	}
	var names []string
	for _, p := range idp.Providers {
		if slices.Contains(oktaRoutes, p.Type) {
			continue
		}
		i := slices.IndexFunc(r.idps, func(listed okta.IdentityProvider) bool { return listed.ID == p.ID })
		switch {
		case i >= 0 && r.idps[i].Name != "":
			names = append(names, r.idps[i].Name)
		default:
			names = append(names, cmp.Or(p.Name, "a "+p.Type+" identity provider"))
		}
	}
	return names
}

// holdsPassword reports whether Okta holds or checks a password for u. A
// federated or social provider's users have none and sign in only through
// an identity provider.
func holdsPassword(u okta.User) bool {
	switch u.Credentials.Provider.Type {
	case "FEDERATION", "SOCIAL":
		return false
	}
	return true
}

// matchesUser reports whether a routing rule's user identifier condition
// can match u. No condition matches everyone. The collector reads only the
// login and email attributes, so a rule on another attribute, a pattern type
// the collector doesn't know, or an expression Go can't compile counts as
// matching, and a rule that might send u elsewhere does.
func matchesUser(cond *okta.UserIdentifierCondition, u okta.User) bool {
	if cond == nil || len(cond.Patterns) == 0 {
		return true
	}
	value := u.Profile.Login
	if cond.Type == "ATTRIBUTE" {
		switch cond.Attribute {
		case "login":
		case "email":
			value = u.Profile.Email
		default:
			return true
		}
	}
	value = strings.ToLower(value)
	return slices.ContainsFunc(cond.Patterns, func(p okta.UserIdentifierPattern) bool {
		pattern := strings.ToLower(p.Value)
		switch p.MatchType {
		case "EQUALS":
			return value == pattern
		case "STARTS_WITH":
			return strings.HasPrefix(value, pattern)
		case "CONTAINS":
			return strings.Contains(value, pattern)
		case "SUFFIX":
			return strings.HasSuffix(value, pattern)
		case "EXPRESSION":
			re, err := regexp.Compile("(?i)" + p.Value)
			return err != nil || re.MatchString(value)
		}
		return true
	})
}

// limitsSignIns reports whether a routing rule names networks, platforms or
// apps, so it sees only some of a user's sign-ins.
func limitsSignIns(c okta.PolicyRuleConditions) bool {
	if c.Network != nil && c.Network.Connection != "" && c.Network.Connection != "ANYWHERE" {
		return true
	}
	if c.App != nil && len(c.App.Include)+len(c.App.Exclude) > 0 {
		return true
	}
	if c.Platform != nil {
		any := func(p okta.RoutingPlatform) bool { return p.Type == "ANY" && (p.OS.Type == "" || p.OS.Type == "ANY") }
		return len(c.Platform.Exclude) > 0 || !slices.ContainsFunc(c.Platform.Include, any) && len(c.Platform.Include) > 0
	}
	return false
}

// The normalized values left out when users, or admins, sign in through
// another identity provider. The counts are audit-level fields.
var (
	usersElsewhere = []struct {
		pointer string
		audit   bool
	}{
		{"/policy/mfa_required", false},
		{"/policy/mfa_required_coverage_pct", false},
		{"/policy/mfa_required_user_count", true},
		{"/user_security/mfa_coverage_pct", false},
		{"/user_security/mfa_phishing_resistant_pct", false},
		{"/user_security/mfa_user_count", true},
		{"/user_security/phishing_resistant_user_count", true},
	}
	adminsElsewhere = []struct {
		pointer string
		audit   bool
	}{
		{"/privileged_access/privileged_mfa_coverage_pct", false},
		{"/privileged_access/privileged_mfa_user_count", true},
		{"/privileged_access/privileged_phishing_resistant_pct", false},
		{"/privileged_access/privileged_phishing_resistant_user_count", true},
	}
)

// markSignInElsewhere records why ToIDPPosture left the MFA values out: an
// unsupported gap that names the other providers, or the gap of the routing
// rules' read. Only audit and higher runs write the counts.
func (c *Collector) markSignInElsewhere(e signInElsewhere, level componentsdk.Level) {
	for _, group := range []struct {
		who    string
		names  []string
		values []struct {
			pointer string
			audit   bool
		}
	}{
		{"users", e.users, usersElsewhere},
		{"admins", e.admins, adminsElsewhere},
	} {
		if len(group.names) == 0 && e.err == nil {
			continue
		}
		detail := "Some " + group.who + " sign in through another identity provider, which decides whether they use MFA: " + strings.Join(group.names, ", ") + "."
		for _, v := range group.values {
			if v.audit && !level.AtLeast(componentsdk.LevelAudit) {
				continue
			}
			at := componentsdk.Location{Path: idpPosturePath, Pointer: v.pointer}
			if e.err != nil {
				c.gaps.rec.NotCollected(at, e.err, gapOptions(e.err)...)
				continue
			}
			c.gaps.rec.NotCollectedCode(at, componentsdk.CodeUnsupported, detail)
		}
	}
}

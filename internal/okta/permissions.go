package okta

import "net/http"

// operationScopes maps each management API call to the OAuth scope Okta's
// API reference lists for it. The collector result lists the scope with the
// call. An API token has no scopes and acts with its owner's admin roles, so
// the sign-in call as an API token names none.
var operationScopes = map[string]string{
	"okta.users.list":                 "okta.users.read",
	"okta.users.factors.list":         "okta.users.read",
	"okta.users.groups.list":          "okta.users.read",
	"okta.users.roles.list":           "okta.roles.read",
	"okta.iam.assignees.list":         "okta.roles.read",
	"okta.iam.roles.list":             "okta.roles.read",
	"okta.iam.roles.permissions.list": "okta.roles.read",
	"okta.apps.list":                  "okta.apps.read",
	"okta.policies.list":              "okta.policies.read",
	"okta.policies.rules.list":        "okta.policies.read",
	"okta.groups.list":                "okta.groups.read",
	"okta.groups.users.list":          "okta.groups.read",
	"okta.device_assurances.list":     "okta.deviceAssurance.read",
	"okta.authenticators.list":        "okta.authenticators.read",
	"okta.zones.list":                 "okta.networkZones.read",
	"okta.idps.list":                  "okta.idps.read",
	"okta.api_tokens.list":            "okta.apiTokens.read",
	"okta.event_hooks.list":           "okta.eventHooks.read",
	"okta.inline_hooks.list":          "okta.inlineHooks.read",
	"okta.logs.list":                  "okta.logs.read",
	"okta.org.get":                    "okta.orgs.read",
	"okta.org.contacts.get":           "okta.orgs.read",
}

// Scope returns the OAuth scope the call named op needs, or "" for a call
// that needs none.
func Scope(op string) string { return operationScopes[op] }

// NamesPermission is componentsdk.HTTPOptions.NamesPermission. Okta refuses
// a token that lacks a scope and an admin role that lacks a permission with
// the same E0000006 answer. The answer alone does not show which one is
// missing, so it never names the scope. The collector names it on a gap
// when the service app asked for the scope and Okta did not grant it.
func NamesPermission(*http.Response, []byte) bool { return false }

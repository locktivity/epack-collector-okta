package collector

// User status values.
const (
	StatusActive          = "ACTIVE"
	StatusDeprovisioned   = "DEPROVISIONED"
	StatusPasswordExpired = "PASSWORD_EXPIRED"
	StatusLockedOut       = "LOCKED_OUT"
	StatusSuspended       = "SUSPENDED"
	StatusRecovery        = "RECOVERY"
)

// App status of a deactivated app.
const AppStatusInactive = "INACTIVE"

// App type of an API service app in the inventory.
const AppTypeService = "SERVICE"

// Group type of the groups Okta manages itself, such as Everyone.
const GroupTypeBuiltIn = "BUILT_IN"

// Policy types.
const (
	PolicyTypeSignOn    = "OKTA_SIGN_ON"
	PolicyTypeMFAEnroll = "MFA_ENROLL"
	PolicyTypePassword  = "PASSWORD"
)

// Policy scope summaries.
const (
	ScopeGroupAssigned = "group-assigned"
	ScopeEveryone      = "everyone"
)

// Policy rule access values.
const (
	AccessAllow = "ALLOW"
	AccessDeny  = "DENY"
)

// Sign-on modes (SSO protocols).
const (
	SignOnModeSAML20       = "SAML_2_0"
	SignOnModeSAML11       = "SAML_1_1"
	SignOnModeOIDC         = "OPENID_CONNECT"
	SignOnModeWSFederation = "WS_FEDERATION"
)

// Application provisioning features.
const (
	FeaturePushNewUsers         = "PUSH_NEW_USERS"
	FeatureImportNewUsers       = "IMPORT_NEW_USERS"
	FeaturePushUserDeactivation = "PUSH_USER_DEACTIVATION"
)

// Phishing-resistant factor types.
const (
	FactorTypeWebAuthn = "webauthn"     // FIDO2 / security keys
	FactorTypeU2F      = "u2f"          // legacy security keys
	FactorTypeFastPass = "signed_nonce" // Okta FastPass (device-bound key)
)

// FactorTypeQuestion is a security question, which is not MFA.
const FactorTypeQuestion = "question"

// phishingResistantFactorTypes is the set of factor types Okta considers
// phishing-resistant. FastPass (signed_nonce) is included because it binds to a
// device-held key, like WebAuthn/U2F.
var phishingResistantFactorTypes = map[string]bool{
	FactorTypeWebAuthn: true,
	FactorTypeU2F:      true,
	FactorTypeFastPass: true,
}

// Role types.
const RoleTypeSuperAdmin = "SUPER_ADMIN"

// Percentage constants.
const MaxPercentage = 100

// Per-surface output caps for internal-level inventories on very large orgs.
// Keep internal-level artifacts within the per-collector size limit.
const (
	UsersCap            = 50000  // sorted ACTIVE-first then login-asc
	AppsCap             = 5000   // sorted ACTIVE-first then label-asc
	GroupsCap           = 10000  // sorted member-count-desc
	GroupMembershipsCap = 200000 // total member-rows across all groups
	SystemLogCap        = 5000   // sorted published-desc
)

package collector

// User status values.
const (
	StatusActive          = "ACTIVE"
	StatusDeprovisioned   = "DEPROVISIONED"
	StatusPasswordExpired = "PASSWORD_EXPIRED"
	StatusLockedOut       = "LOCKED_OUT"
	StatusSuspended       = "SUSPENDED"
)

// Policy types.
const (
	PolicyTypeSignOn    = "OKTA_SIGN_ON"
	PolicyTypeMFAEnroll = "MFA_ENROLL"
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

// MFA enrollment actions.
const (
	MFAActionChallenge = "CHALLENGE"
	MFAActionLogin     = "LOGIN"
)

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

package collector

// User status values.
const (
	StatusActive          = "ACTIVE"
	StatusDeprovisioned   = "DEPROVISIONED"
	StatusPasswordExpired = "PASSWORD_EXPIRED"
	StatusLockedOut       = "LOCKED_OUT"
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
	FeaturePushNewUsers        = "PUSH_NEW_USERS"
	FeatureImportNewUsers      = "IMPORT_NEW_USERS"
	FeaturePushUserDeactivation = "PUSH_USER_DEACTIVATION"
)

// Phishing-resistant factor types.
const (
	FactorTypeWebAuthn = "webauthn"
	FactorTypeU2F      = "u2f"
)

// MFA enrollment actions.
const (
	MFAActionChallenge = "CHALLENGE"
	MFAActionLogin     = "LOGIN"
)

// Percentage constants.
const MaxPercentage = 100

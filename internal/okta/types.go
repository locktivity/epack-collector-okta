// Package okta provides Okta API client functionality.
package okta

import "time"

// User represents an Okta user.
type User struct {
	ID              string      `json:"id"`
	Status          string      `json:"status"` // STAGED, PROVISIONED, ACTIVE, RECOVERY, LOCKED_OUT, PASSWORD_EXPIRED, SUSPENDED, DEPROVISIONED
	Created         time.Time   `json:"created"`
	Activated       time.Time   `json:"activated"`
	LastLogin       time.Time   `json:"lastLogin"`
	LastUpdated     time.Time   `json:"lastUpdated"`
	PasswordChanged time.Time   `json:"passwordChanged"`
	Profile         UserProfile `json:"profile"`
}

// UserProfile contains user profile information.
type UserProfile struct {
	Login     string `json:"login"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	UserType  string `json:"userType"`
}

// Factor represents an MFA factor enrolled by a user.
type Factor struct {
	ID         string `json:"id"`
	FactorType string `json:"factorType"` // sms, call, email, token:software:totp, token:hotp, push, u2f, webauthn, token:hardware, question
	Provider   string `json:"provider"`   // OKTA, GOOGLE, RSA, SYMANTEC, YUBICO, etc.
	VendorName string `json:"vendorName"`
	Status     string `json:"status"` // ACTIVE, PENDING_ACTIVATION, ENROLLED, INACTIVE, NOT_SETUP
}

// Application represents an Okta application.
type Application struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Label       string        `json:"label"`
	Status      string        `json:"status"`     // ACTIVE, INACTIVE
	SignOnMode  string        `json:"signOnMode"` // SAML_2_0, OPENID_CONNECT, WS_FEDERATION, BROWSER_PLUGIN, etc.
	Created     time.Time     `json:"created"`
	LastUpdated time.Time     `json:"lastUpdated"`
	Features    []string      `json:"features"` // PUSH_NEW_USERS, PUSH_USER_DEACTIVATION, etc.
	Visibility  AppVisibility `json:"visibility"`
}

// AppVisibility contains application visibility settings.
type AppVisibility struct {
	AutoSubmitToolbar bool `json:"autoSubmitToolbar"`
	Hide              struct {
		IOS bool `json:"iOS"`
		Web bool `json:"web"`
	} `json:"hide"`
}

// Policy represents an Okta policy.
type Policy struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Type       string           `json:"type"`   // OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, ACCESS_POLICY
	Status     string           `json:"status"` // ACTIVE, INACTIVE
	Priority   int              `json:"priority"`
	System     bool             `json:"system"` // Is this a system policy?
	Conditions PolicyConditions `json:"conditions"`
	Settings   PolicySettings   `json:"settings"`
}

// PolicyConditions contains policy conditions.
type PolicyConditions struct {
	People *PolicyPeopleCondition `json:"people,omitempty"`
}

// PolicyPeopleCondition specifies which users/groups a policy applies to.
type PolicyPeopleCondition struct {
	Groups *struct {
		Include []string `json:"include,omitempty"`
		Exclude []string `json:"exclude,omitempty"`
	} `json:"groups,omitempty"`
	Users *struct {
		Include []string `json:"include,omitempty"`
		Exclude []string `json:"exclude,omitempty"`
	} `json:"users,omitempty"`
}

// PolicySettings contains policy settings.
type PolicySettings struct {
	// Password policy settings
	Password *PasswordPolicySettings `json:"password,omitempty"`

	// Recovery settings
	Recovery *RecoverySettings `json:"recovery,omitempty"`

	// Delegation settings
	Delegation *DelegationSettings `json:"delegation,omitempty"`
}

// PasswordPolicySettings contains password policy configuration.
type PasswordPolicySettings struct {
	Complexity *PasswordComplexity `json:"complexity,omitempty"`
	Age        *PasswordAge        `json:"age,omitempty"`
	Lockout    *PasswordLockout    `json:"lockout,omitempty"`
}

// PasswordComplexity defines password complexity requirements.
type PasswordComplexity struct {
	MinLength         int      `json:"minLength"`
	MinLowerCase      int      `json:"minLowerCase"`
	MinUpperCase      int      `json:"minUpperCase"`
	MinNumber         int      `json:"minNumber"`
	MinSymbol         int      `json:"minSymbol"`
	ExcludeUsername   bool     `json:"excludeUsername"`
	ExcludeAttributes []string `json:"excludeAttributes"`
}

// PasswordAge defines password age requirements.
type PasswordAge struct {
	MaxAgeDays     int `json:"maxAgeDays"`
	ExpireWarnDays int `json:"expireWarnDays"`
	MinAgeMinutes  int `json:"minAgeMinutes"`
	HistoryCount   int `json:"historyCount"`
}

// PasswordLockout defines lockout settings.
type PasswordLockout struct {
	MaxAttempts         int  `json:"maxAttempts"`
	AutoUnlockMinutes   int  `json:"autoUnlockMinutes"`
	ShowLockoutFailures bool `json:"showLockoutFailures"`
}

// RecoverySettings contains account recovery settings.
type RecoverySettings struct {
	Factors *RecoveryFactors `json:"factors,omitempty"`
}

// RecoveryFactors defines allowed recovery factors.
type RecoveryFactors struct {
	RecoveryQuestion *RecoveryQuestionSettings `json:"recovery_question,omitempty"`
	OktaEmail        *RecoveryEmailSettings    `json:"okta_email,omitempty"`
	OktaSMS          *RecoverySMSSettings      `json:"okta_sms,omitempty"`
	OktaCall         *RecoveryCallSettings     `json:"okta_call,omitempty"`
}

// RecoveryQuestionSettings for recovery question factor.
type RecoveryQuestionSettings struct {
	Status     string `json:"status"` // ACTIVE, INACTIVE
	Properties struct {
		Complexity struct {
			MinLength int `json:"minLength"`
		} `json:"complexity"`
	} `json:"properties"`
}

// RecoveryEmailSettings for email recovery factor.
type RecoveryEmailSettings struct {
	Status     string `json:"status"`
	Properties struct {
		RecoveryToken struct {
			TokenLifetimeMinutes int `json:"tokenLifetimeMinutes"`
		} `json:"recoveryToken"`
	} `json:"properties"`
}

// RecoverySMSSettings for SMS recovery factor.
type RecoverySMSSettings struct {
	Status string `json:"status"`
}

// RecoveryCallSettings for voice call recovery factor.
type RecoveryCallSettings struct {
	Status string `json:"status"`
}

// DelegationSettings contains delegation settings.
type DelegationSettings struct {
	Options struct {
		SkipUnlock bool `json:"skipUnlock"`
	} `json:"options"`
}

// PolicyRule represents a rule within a policy.
type PolicyRule struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Status     string               `json:"status"` // ACTIVE, INACTIVE
	Priority   int                  `json:"priority"`
	System     bool                 `json:"system"`
	Type       string               `json:"type"`
	Conditions PolicyRuleConditions `json:"conditions"`
	Actions    PolicyRuleActions    `json:"actions"`
}

// PolicyRuleConditions contains rule conditions.
type PolicyRuleConditions struct {
	People  *PolicyPeopleCondition `json:"people,omitempty"`
	Network *struct {
		Connection string   `json:"connection"` // ANYWHERE, ZONE, ON_NETWORK
		Include    []string `json:"include,omitempty"`
		Exclude    []string `json:"exclude,omitempty"`
	} `json:"network,omitempty"`
}

// PolicyRuleActions contains rule actions.
type PolicyRuleActions struct {
	Signon *SignonActions `json:"signon,omitempty"`
	Enroll *EnrollActions `json:"enroll,omitempty"`
}

// SignonActions for sign-on policy rules.
type SignonActions struct {
	Access                  string `json:"access"` // ALLOW, DENY
	RequireFactor           bool   `json:"requireFactor"`
	FactorPromptMode        string `json:"factorPromptMode"` // ALWAYS, DEVICE, SESSION
	RememberDeviceByDefault bool   `json:"rememberDeviceByDefault"`
	FactorLifetime          int    `json:"factorLifetime"` // Minutes
	Session                 struct {
		UsePersistentCookie       bool `json:"usePersistentCookie"`
		MaxSessionIdleMinutes     int  `json:"maxSessionIdleMinutes"`
		MaxSessionLifetimeMinutes int  `json:"maxSessionLifetimeMinutes"`
	} `json:"session"`
}

// EnrollActions for MFA enrollment policy rules.
type EnrollActions struct {
	Self string `json:"self"` // CHALLENGE, LOGIN, NEVER
}

// Group represents an Okta group.
type Group struct {
	ID      string       `json:"id"`
	Created time.Time    `json:"created"`
	Profile GroupProfile `json:"profile"`
	Type    string       `json:"type"` // OKTA_GROUP, APP_GROUP, BUILT_IN
}

// GroupProfile contains group profile information.
type GroupProfile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// OrgSettings represents Okta organization settings.
type OrgSettings struct {
	ID          string    `json:"id"`
	Subdomain   string    `json:"subdomain"`
	CompanyName string    `json:"companyName"`
	Status      string    `json:"status"`
	Created     time.Time `json:"created"`
}

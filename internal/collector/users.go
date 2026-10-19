package collector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk"
)

// userMetricsCollector holds intermediate user collection state.
type userMetricsCollector struct {
	err                  error // the user list could not be read
	totalUsers           int
	mfaEnrolledCount     int
	mfaPhishingResistant int
	passwordExpired      int
	lockedOut            int
	inactive             int
	suspended            int
	users                []okta.User // Collected users for second pass
	userByID             map[string]okta.User
	hasMFAByUser         map[string]bool
	hasPhishingByUser    map[string]bool
	factorErrs           map[string]error // users whose factors could not be read
	firstFactorErr       error
	// Audit-level accumulation (populated only when level >= audit).
	inventory          []User // Per-user inventory rows
	inventoryTruncated bool
	inventoryDropped   int
	factorTypeCounts   map[string]int // active factor type -> distinct enrolled users
}

// factorFailures counts the users whose factors could not be read.
func (m *userMetricsCollector) factorFailures() int {
	return len(m.factorErrs)
}

// loginByID maps each listed user's ID to their login.
func (m *userMetricsCollector) loginByID() map[string]string {
	logins := make(map[string]string, len(m.userByID))
	for id, u := range m.userByID {
		logins[id] = u.Profile.Login
	}
	return logins
}

func (c *Collector) collectUserMetrics(ctx context.Context, level componentsdk.Level) *userMetricsCollector {
	metrics := &userMetricsCollector{
		userByID:          make(map[string]okta.User),
		hasMFAByUser:      make(map[string]bool),
		hasPhishingByUser: make(map[string]bool),
		factorErrs:        make(map[string]error),
		factorTypeCounts:  make(map[string]int),
	}
	inactiveThreshold := c.config.now().AddDate(0, 0, -InactiveDaysThreshold)

	// First pass: fetch all users. A page that fails fails the whole list, so
	// a partial list never stands in for the org.
	var users []okta.User
	err := c.client.FetchUsers(ctx, func(page []okta.User) error {
		users = append(users, page...)
		c.status(fmt.Sprintf("Found %d users...", len(users)))
		return nil
	})
	if err != nil {
		c.warnSurface("users", "okta.users.read", err)
		metrics.err = err
		return metrics
	}
	metrics.users = users
	for _, user := range users {
		metrics.userByID[user.ID] = user
	}

	// Second pass: check MFA factors for each user
	total := int64(len(metrics.users))
	for i, user := range metrics.users {
		c.progress(int64(i+1), total, fmt.Sprintf("Checking MFA for user %d of %d", i+1, len(metrics.users)))
		c.processUser(ctx, user, inactiveThreshold, metrics, level)
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		// ACTIVE users first, then login ascending: on cap-hit the most
		// security-relevant (active) rows stick.
		metrics.inventory, metrics.inventoryDropped, metrics.inventoryTruncated = Truncate(metrics.inventory, UsersCap, func(a, b User) bool {
			aActive := a.Status == StatusActive
			bActive := b.Status == StatusActive
			if aActive != bActive {
				return aActive
			}
			return a.Login < b.Login
		})
		if metrics.inventoryTruncated {
			c.warn("users: inventory truncated to %d (dropped %d)", UsersCap, metrics.inventoryDropped)
		}
	}

	return metrics
}

// fillUsers writes the user metrics into the posture, leaving out with a gap
// each value the reads it needs did not give.
func (c *Collector) fillUsers(p *OrgPosture, m *userMetricsCollector, level componentsdk.Level) {
	audit := level.AtLeast(componentsdk.LevelAudit)
	if m.err != nil {
		c.gaps.notCollected(m.err,
			"/users/total_count", "/users/password_expired", "/users/locked_out", "/users/inactive", "/users/suspended",
			"/posture/mfa_coverage", "/posture/mfa_phishing_resistant")
		if audit {
			c.gaps.notCollected(m.err, "/users/inventory", "/posture/mfa_disabled_users_count")
		}
		return
	}

	total := m.totalUsers
	p.Users.TotalCount = intPtr(total)
	p.Users.PasswordExpired = percent(m.passwordExpired, total)
	p.Users.LockedOut = percent(m.lockedOut, total)
	p.Users.Inactive = percent(m.inactive, total)
	p.Users.Suspended = percent(m.suspended, total)

	if failed := m.factorFailures(); failed > 0 {
		c.gaps.partial(failed, m.firstFactorErr, "/posture/mfa_coverage", "/posture/mfa_phishing_resistant")
		if audit {
			c.gaps.partial(failed, m.firstFactorErr, "/posture/mfa_disabled_users_count")
		}
	} else {
		p.Posture.MFACoverage = percent(m.mfaEnrolledCount, total)
		p.Posture.MFAPhishingResistant = percent(m.mfaPhishingResistant, total)
		if audit {
			p.Posture.MFADisabledUsersCount = intPtr(total - m.mfaEnrolledCount)
		}
	}

	if !audit {
		return
	}
	p.Users.Inventory = m.inventory
	p.Users.InventoryTruncated = m.inventoryTruncated
	p.Users.InventoryDropped = m.inventoryDropped
	for i, row := range m.inventory {
		if row.factorsErr != nil {
			c.gaps.notCollected(row.factorsErr, rowPointer("/users/inventory", i, "factors"))
		}
		if row.groupsErr != nil {
			c.gaps.notCollected(row.groupsErr, rowPointer("/users/inventory", i, "group_ids"))
		}
	}
}

// processUser processes a single user and updates metrics.
func (c *Collector) processUser(ctx context.Context, user okta.User, inactiveThreshold time.Time, metrics *userMetricsCollector, level componentsdk.Level) {
	if user.Status == StatusDeprovisioned {
		return
	}

	metrics.totalUsers++

	if user.LastLogin.IsZero() || user.LastLogin.Before(inactiveThreshold) {
		metrics.inactive++
	}

	switch user.Status {
	case StatusPasswordExpired:
		metrics.passwordExpired++
	case StatusLockedOut:
		metrics.lockedOut++
	case StatusSuspended:
		metrics.suspended++
	}

	factors, factorsErr := c.processUserFactors(ctx, user.ID, metrics, level)

	if level.AtLeast(componentsdk.LevelAudit) {
		row := userInventoryRow(user)
		if level.AtLeast(componentsdk.LevelInternal) {
			c.enrichUserRowInternal(ctx, &row, user, factors, factorsErr)
		}
		metrics.inventory = append(metrics.inventory, row)
	}
}

// enrichUserRowInternal adds internal-level activity timestamps, the enrolled
// factor list, and group-membership IDs to a user inventory row. A list that
// could not be read is left out, and its error kept for the gap.
func (c *Collector) enrichUserRowInternal(ctx context.Context, row *User, user okta.User, factors []UserFactor, factorsErr error) {
	row.LastLoginAt = formatTime(user.LastLogin)
	row.LastUpdatedAt = formatTime(user.LastUpdated)
	row.StatusChangedAt = formatTime(user.StatusChanged)
	row.PasswordChangedAt = formatTime(user.PasswordChanged)

	if factorsErr != nil {
		row.factorsErr = factorsErr
	} else {
		if factors == nil {
			factors = []UserFactor{}
		}
		row.Factors = factors
	}

	groupIDs, err := c.client.FetchUserGroupIDs(ctx, user.ID)
	if err != nil {
		c.warn("user %s: failed to fetch group memberships: %v", user.ID, err)
		row.groupsErr = err
		return
	}
	row.GroupIDs = groupIDs
}

// userInventoryRow projects an okta.User onto its audit-level inventory row.
func userInventoryRow(user okta.User) User {
	row := User{
		Login:     user.Profile.Login,
		Status:    user.Status,
		UserType:  classifyUserType(user),
		CreatedAt: formatTime(user.Created),
	}
	return row
}

// classifyUserType buckets a user into a coarse "Human" / "Service" label. Okta
// has no canonical service-account flag, so this reads the customer-set userType
// profile attribute and matches service-account naming conventions. The raw
// attribute value is never emitted, only the bucket.
func classifyUserType(user okta.User) string {
	raw := strings.ToLower(user.Profile.UserType) // LINT-ALLOW: derive coarse Human/Service bucket; raw value never emitted
	for _, marker := range []string{"service", "svc", "bot", "system", "integration", "machine"} {
		if strings.Contains(raw, marker) {
			return "Service"
		}
	}
	return "Human"
}

// processUserFactors checks MFA factors for a user, updating aggregate metrics.
// At internal level it returns the user's active factors as inventory rows. A
// user whose factors could not be read is counted as unmeasured, never as
// unenrolled.
func (c *Collector) processUserFactors(ctx context.Context, userID string, metrics *userMetricsCollector, level componentsdk.Level) ([]UserFactor, error) {
	factors, err := c.client.FetchUserFactors(ctx, userID)
	if err != nil {
		c.warn("user %s: failed to fetch MFA factors: %v", userID, err)
		metrics.factorErrs[userID] = err
		if metrics.firstFactorErr == nil {
			metrics.firstFactorErr = err
		}
		return nil, err
	}

	hasMFA := false
	hasPhishingResistant := false
	seenFactorTypes := make(map[string]struct{})
	var activeFactors []UserFactor

	for _, factor := range factors {
		if factor.Status != StatusActive {
			continue
		}

		hasMFA = true

		factorType := strings.ToLower(factor.FactorType)
		if phishingResistantFactorTypes[factorType] {
			hasPhishingResistant = true
		}

		if level.AtLeast(componentsdk.LevelAudit) {
			if _, seen := seenFactorTypes[factorType]; !seen {
				seenFactorTypes[factorType] = struct{}{}
				metrics.factorTypeCounts[factorType]++
			}
		}

		if level.AtLeast(componentsdk.LevelInternal) {
			activeFactors = append(activeFactors, UserFactor{
				FactorType: factor.FactorType,
				Status:     factor.Status,
				EnrolledAt: formatTime(factor.Created),
			})
		}
	}

	if hasMFA {
		metrics.mfaEnrolledCount++
	}
	if hasPhishingResistant {
		metrics.mfaPhishingResistant++
	}

	metrics.hasMFAByUser[userID] = hasMFA
	metrics.hasPhishingByUser[userID] = hasPhishingResistant

	return activeFactors, nil
}

// authenticatorKeyToFactorType maps org-level authenticator catalog keys to the
// factor type reported by the per-user factors API. Used to seed zero-count
// entries for enabled-but-unenrolled authenticators. Best-effort: keys without a
// confident mapping are skipped (observed factors still surface them).
var authenticatorKeyToFactorType = map[string]string{
	"okta_verify":       "push",
	"google_otp":        "token:software:totp",
	"webauthn":          "webauthn",
	"phone_number":      "sms",
	"okta_email":        "email",
	"security_question": "question",
}

// collectAuthenticatorMetrics builds the audit-level per-factor-type enrollment
// counts. Counts come from the accumulated per-user factor iteration; the
// org-level authenticator catalog is fetched to seed zero-count entries for
// enabled authenticators with no enrollments. Returns nil below audit level,
// and nil with a gap when the users, their factors, or the catalog could not
// be read.
func (c *Collector) collectAuthenticatorMetrics(ctx context.Context, userMetrics *userMetricsCollector, level componentsdk.Level) []FactorTypeCount {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}

	switch {
	case userMetrics.err != nil:
		c.gaps.notCollected(userMetrics.err, "/posture/per_factor_type")
		return nil
	case userMetrics.factorFailures() > 0:
		c.gaps.partial(userMetrics.factorFailures(), userMetrics.firstFactorErr, "/posture/per_factor_type")
		return nil
	}

	authenticators, err := c.client.ListAuthenticators(ctx)
	if err != nil {
		c.warnSurface("authenticators", "okta.authenticators.read", err)
		c.gaps.notCollected(err, "/posture/per_factor_type")
		return nil
	}

	counts := make(map[string]int, len(userMetrics.factorTypeCounts))
	for factorType, n := range userMetrics.factorTypeCounts {
		counts[factorType] = n
	}
	for _, a := range authenticators {
		if a.Status != StatusActive {
			continue
		}
		if factorType, ok := authenticatorKeyToFactorType[a.Key]; ok {
			if _, present := counts[factorType]; !present {
				counts[factorType] = 0
			}
		}
	}

	factorTypes := make([]string, 0, len(counts))
	for factorType := range counts {
		factorTypes = append(factorTypes, factorType)
	}
	sort.Strings(factorTypes)

	result := make([]FactorTypeCount, 0, len(factorTypes))
	for _, factorType := range factorTypes {
		result = append(result, FactorTypeCount{FactorType: factorType, EnrolledUsers: counts[factorType]})
	}
	return result
}

// UserMetrics contains user status percentages (all 0-100). Each is null when
// the user list could not be read or the org has no users.
//
// Audit adds the per-user inventory (login + status + type + created-at). Internal
// adds per-user activity timestamps, factor lists, and group membership.
type UserMetrics struct {
	TotalCount      *int `json:"total_count"`      // Users other than deprovisioned ones; the population of the user percentages
	PasswordExpired *int `json:"password_expired"` // % users with expired passwords
	LockedOut       *int `json:"locked_out"`       // % users currently locked out
	Inactive        *int `json:"inactive"`         // % users inactive for 90+ days
	Suspended       *int `json:"suspended"`        // % users currently suspended

	// Audit-level field.
	Inventory          []User `json:"inventory,omitempty"`
	InventoryTruncated bool   `json:"inventory_truncated,omitempty"`
	InventoryDropped   int    `json:"inventory_dropped,omitempty"`
}

// User is a per-user inventory row (audit+). Login is the only identifier
// emitted; profile attributes beyond login are intentionally excluded.
//
// Internal adds per-user activity timestamps, the enrolled-factor list, and the
// group-membership ID list.
type User struct {
	Login     string `json:"login"`
	Status    string `json:"status"`
	UserType  string `json:"user_type"` // Coarse "Human" / "Service" classification
	CreatedAt string `json:"created_at,omitempty"`

	// Internal-level fields.
	LastLoginAt       string       `json:"last_login_at,omitempty"`
	LastUpdatedAt     string       `json:"last_updated_at,omitempty"`
	StatusChangedAt   string       `json:"status_changed_at,omitempty"`
	PasswordChangedAt string       `json:"password_changed_at,omitempty"`
	Factors           []UserFactor `json:"factors,omitempty"`
	GroupIDs          []string     `json:"group_ids,omitempty"`

	factorsErr error
	groupsErr  error
}

// UserFactor is a per-user enrolled MFA factor (internal).
type UserFactor struct {
	FactorType string `json:"factor_type"`
	Status     string `json:"status"`
	EnrolledAt string `json:"enrolled_at,omitempty"`
}

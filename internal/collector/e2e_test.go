//go:build e2e
// +build e2e

package collector

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// E2E tests run against a real Okta organization.
//
// Required environment variables:
//
//	OKTA_ORG_DOMAIN    - Okta organization domain (e.g., "dev-12345.okta.com")
//
// Authentication (one of the following):
//
//	OAuth 2.0 (recommended):
//	  OKTA_CLIENT_ID     - OAuth 2.0 client ID
//	  OKTA_PRIVATE_KEY   - PEM-encoded RSA private key
//
//	API Token (legacy):
//	  OKTA_API_TOKEN     - SSWS API token
//
// Run with:
//
//	go test -tags=e2e -v ./internal/collector/...

func getE2EConfig(t *testing.T) Config {
	t.Helper()

	orgDomain := os.Getenv("OKTA_ORG_DOMAIN")
	if orgDomain == "" {
		t.Skip("OKTA_ORG_DOMAIN not set, skipping e2e test")
	}

	config := Config{
		OrgDomain:  orgDomain,
		ClientID:   os.Getenv("OKTA_CLIENT_ID"),
		PrivateKey: os.Getenv("OKTA_PRIVATE_KEY"),
		APIToken:   os.Getenv("OKTA_API_TOKEN"),
	}

	hasOAuth := config.ClientID != "" && config.PrivateKey != ""
	hasToken := config.APIToken != ""

	if !hasOAuth && !hasToken {
		t.Skip("No authentication configured. Set OKTA_CLIENT_ID + OKTA_PRIVATE_KEY or OKTA_API_TOKEN")
	}

	return config
}

func TestE2E_RealOktaCollection(t *testing.T) {
	config := getE2EConfig(t)

	collector, err := New(config)
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	posture, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	// Validate basic structure
	if posture.SchemaVersion != SchemaVersion {
		t.Errorf("expected schema version %s, got %s", SchemaVersion, posture.SchemaVersion)
	}

	if posture.OrgDomain != config.OrgDomain {
		t.Errorf("expected org domain %s, got %s", config.OrgDomain, posture.OrgDomain)
	}

	if posture.CollectedAt == "" {
		t.Error("collected_at should not be empty")
	}

	// Log the results for inspection
	t.Logf("Collection successful!")
	t.Logf("  Org Domain: %s", posture.OrgDomain)
	t.Logf("  MFA Coverage: %d%%", posture.Posture.MFACoverage)
	t.Logf("  MFA Phishing Resistant: %d%%", posture.Posture.MFAPhishingResistant)
	t.Logf("  SSO Coverage: %d%%", posture.Posture.SSOCoverage)

	// Output full JSON for debugging
	data, _ := json.MarshalIndent(posture, "", "  ")
	t.Logf("\nFull posture output:\n%s", string(data))
}

func TestE2E_ValidatePostureMetrics(t *testing.T) {
	config := getE2EConfig(t)

	collector, err := New(config)
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	posture, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	// All percentage fields should be 0-100
	percentFields := []struct {
		name  string
		value int
	}{
		{"posture.mfa_coverage", posture.Posture.MFACoverage},
		{"posture.mfa_phishing_resistant", posture.Posture.MFAPhishingResistant},
		{"posture.sso_coverage", posture.Posture.SSOCoverage},
		{"users.password_expired", posture.Users.PasswordExpired},
		{"users.locked_out", posture.Users.LockedOut},
		{"users.inactive", posture.Users.Inactive},
		{"apps.provisioning_enabled", posture.Apps.ProvisioningEnabled},
		{"apps.deprovisioning_enabled", posture.Apps.DeprovisioningEnabled},
	}

	for _, pf := range percentFields {
		if pf.value < 0 || pf.value > 100 {
			t.Errorf("%s should be 0-100, got %d", pf.name, pf.value)
		}
	}

	t.Logf("All metrics validated successfully")
}

func TestE2E_ValidatePolicySettings(t *testing.T) {
	config := getE2EConfig(t)

	collector, err := New(config)
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	posture, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	// Log policy settings
	t.Logf("Policy Count: %d", posture.Policy.PolicyCount)
	t.Logf("MFA Required (all policies): %v", posture.Policy.MFARequiredAll)
	t.Logf("MFA Required (any policy): %v", posture.Policy.MFARequiredAny)

	if posture.Policy.SessionLifetimeMinMinutes != nil {
		t.Logf("Session Lifetime Min: %d minutes", *posture.Policy.SessionLifetimeMinMinutes)
	} else {
		t.Log("Session Lifetime Min: not set")
	}

	if posture.Policy.SessionLifetimeMaxMinutes != nil {
		t.Logf("Session Lifetime Max: %d minutes", *posture.Policy.SessionLifetimeMaxMinutes)
	} else {
		t.Log("Session Lifetime Max: not set")
	}

	if posture.Policy.IdleTimeoutMinMinutes != nil {
		t.Logf("Idle Timeout Min: %d minutes", *posture.Policy.IdleTimeoutMinMinutes)
	} else {
		t.Log("Idle Timeout Min: not set")
	}

	if posture.Policy.IdleTimeoutMaxMinutes != nil {
		t.Logf("Idle Timeout Max: %d minutes", *posture.Policy.IdleTimeoutMaxMinutes)
	} else {
		t.Log("Idle Timeout Max: not set")
	}
}

func TestE2E_OutputValidJSON(t *testing.T) {
	config := getE2EConfig(t)

	collector, err := New(config)
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	posture, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	// Serialize and deserialize to ensure valid JSON
	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("failed to marshal posture: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check required top-level fields
	requiredFields := []string{
		"schema_version",
		"collected_at",
		"org_domain",
		"posture",
		"users",
		"apps",
		"policy",
	}

	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	t.Log("Output JSON structure validated")
}

//go:build record

package collector

import (
	"os"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-okta/internal/okta"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// TestRecord records a sandbox, an Okta org kept with known settings, to
// testdata/recordings/okta.json for the collectortest OAuth suite. It signs
// in as a service app, reading the org's domain, the app's client ID, and
// its key ID from SANDBOX_OKTA_ORG_DOMAIN, SANDBOX_OKTA_COLLECTOR_CLIENT_ID,
// and SANDBOX_OKTA_COLLECTOR_KEY_ID, and the app's private key from
// OKTA_PRIVATE_KEY, and skips when any is not set. The recording names the
// org acme, as in acme.okta.com, and the app by the kit's IDs. The value of
// any other SANDBOX_ variable becomes a stable fake, and Record writes
// nothing if one remains. recordScrubPatterns also remove where each system
// log event came from and the org's company details:
//
//	SANDBOX_OKTA_ORG_DOMAIN=... SANDBOX_OKTA_COLLECTOR_CLIENT_ID=... SANDBOX_OKTA_COLLECTOR_KEY_ID=... \
//	OKTA_PRIVATE_KEY="$(cat key.pem)" go test -tags record -run 'TestRecord/^okta$' -count=1 ./internal/collector/
func TestRecord(t *testing.T) {
	t.Run("okta", func(t *testing.T) {
		orgDomain := os.Getenv("SANDBOX_OKTA_ORG_DOMAIN")
		clientID := os.Getenv("SANDBOX_OKTA_COLLECTOR_CLIENT_ID")
		keyID := os.Getenv("SANDBOX_OKTA_COLLECTOR_KEY_ID")
		privateKey := os.Getenv("OKTA_PRIVATE_KEY")
		if orgDomain == "" || clientID == "" || keyID == "" || privateKey == "" {
			t.Skip("set SANDBOX_OKTA_ORG_DOMAIN, SANDBOX_OKTA_COLLECTOR_CLIENT_ID, SANDBOX_OKTA_COLLECTOR_KEY_ID, and OKTA_PRIVATE_KEY to record")
		}
		identifiers := collectortest.EnvIdentifiers("SANDBOX_", map[string]string{
			"SANDBOX_OKTA_ORG_DOMAIN":          kitOrgDomain,
			"SANDBOX_OKTA_COLLECTOR_CLIENT_ID": kitClientID,
			"SANDBOX_OKTA_COLLECTOR_KEY_ID":    kitKeyID,
		})
		// The subdomain also names the org in its admin host, such as
		// acme-admin.okta.com.
		subdomain, _, _ := strings.Cut(okta.Host(orgDomain), ".")
		identifiers[subdomain] = "acme"
		report, err := collectortest.Record(collectortest.RecordOptions{
			Spec: Spec("record", "collectortest"),
			Run:  Run,
			Config: map[string]any{
				"org_domain": orgDomain,
				"client_id":  clientID,
				"key_id":     keyID,
				"level":      "audit",
			},
			Secrets: map[string]string{"OKTA_PRIVATE_KEY": privateKey},
			Out:     "testdata/recordings/okta.json",
			Scrub:   collectortest.ScrubRules{Identifiers: identifiers, Patterns: recordScrubPatterns},
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.ExitCode != 0 {
			t.Errorf("the recorded run exited %d: %+v", report.ExitCode, report.Failure)
		}
		t.Logf("recorded %d responses", report.Responses)
	})
}

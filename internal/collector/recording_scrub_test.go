package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// jsonStringPattern reads a JSON string whole, so a brace or quote inside it
// is not taken as structure.
const jsonStringPattern = `"(?:[^"\\]|\\.)*"`

// jsonObjectPattern matches a JSON object with objects nested up to three
// levels inside it.
var jsonObjectPattern = func() string {
	body := `(?:` + jsonStringPattern + `|[^{}"])*`
	for range 3 {
		body = `(?:` + jsonStringPattern + `|[^{}"]|\{` + body + `\})*`
	}
	return `\{` + body + `\}`
}()

const recordedUserAgent = `{"rawUserAgent":"example-agent/1.0","os":"Unknown","browser":"UNKNOWN"}`

// recordScrubPatterns remove from a recording what the collector never reads
// and a public repository must not hold: where each system log event came
// from (location, network owner, device and TLS fingerprints, and user
// agent), Okta's debug data for the event, and the org's company and contact
// details. geographicalContext goes first, so the address keys left after it
// are the org's.
var recordScrubPatterns = []collectortest.ScrubPattern{
	scrubMember("geographicalContext", jsonObjectPattern, "null"),
	scrubMember("securityContext", jsonObjectPattern, "null"),
	scrubMember("ipDetails", jsonObjectPattern, "null"),
	scrubMember("debugContext", jsonObjectPattern, "null"),
	scrubMember("device", jsonObjectPattern, "null"),
	scrubMember("userAgent", jsonObjectPattern, recordedUserAgent),
	scrubMember("companyName", jsonStringPattern, `"Example"`),
	scrubMember("website", jsonStringPattern, `"https://example.com"`),
	scrubMember("address1|address2|city|state|postalCode|phoneNumber|supportPhoneNumber|endUserSupportHelpURL", jsonStringPattern, "null"),
}

// scrubMember replaces the value of each JSON member whose name matches keys
// and whose value matches value.
func scrubMember(keys, value, replacement string) collectortest.ScrubPattern {
	return collectortest.ScrubPattern{
		Pattern: regexp.MustCompile(`"(` + keys + `)"\s*:\s*` + value),
		Replace: `"${1}":` + replacement,
	}
}

func TestRecordScrubPatterns(t *testing.T) {
	event := `{"actor":{"alternateId":"user1@example.com","type":"User"},` +
		`"client":{"userAgent":{"rawUserAgent":"Mozilla/5.0 (Macintosh)","os":"Mac OS 14.1.0 (Sonoma)","browser":"CHROME"},"zone":"null","device":"Computer","ipAddress":"192.0.2.1",` +
		`"geographicalContext":{"city":"Springfield","state":"Ohio","country":"United States","postalCode":"45501","geolocation":{"lat":39.9,"lon":-83.8}}},` +
		`"device":{"id":null,"device_integrator":{"DEVICE_IDP":{}}},` +
		`"debugContext":{"debugData":{"dtHash":"00ff","deviceFingerprint":"aa11","logOnlySecurityData":"{\"risk\":{\"level\":\"HIGH\"}}"}},` +
		`"eventType":"user.session.start","outcome":{"result":"SUCCESS"},` +
		`"securityContext":{"asNumber":64496,"asOrg":"example isp","isp":"example isp","domain":"example.net","isProxy":false,` +
		`"ipDetails":{"asNumber":64496,"asOrg":"example isp","isp":"example isp","domain":"example.net"},` +
		`"risk":{"level":"HIGH","reasons":["Anomalous Location"]},"userBehaviors":[{"name":"New IP","result":"NEGATIVE"}],"tlsFingerprint":{"ja4":"t13d0000h2_0000_0000"}},` +
		`"request":{"ipChain":[{"ip":"192.0.2.1","geographicalContext":{"city":"Springfield","geolocation":{"lat":39.9,"lon":-83.8}},"version":"V4",` +
		`"ipDetails":{"asNumber":64496,"asOrg":"example isp","isp":"example isp","domain":"example.net"}}]}}`
	org := `{"id":"00o1","subdomain":"acme","companyName":"Example Company","status":"ACTIVE","website":"https://company.example",` +
		`"phoneNumber":"+1 555 0100","address1":"1 Main St","address2":null,"city":"Springfield","state":"Ohio","country":"United States","postalCode":"45501"}`

	scrub := func(in string) map[string]any {
		t.Helper()
		for _, p := range recordScrubPatterns {
			in = p.Pattern.ReplaceAllString(in, p.Replace)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(in), &out); err != nil {
			t.Fatalf("scrubbed JSON does not parse: %v\n%s", err, in)
		}
		return out
	}

	e := scrub(event)
	if problems := unscrubbed(e, ""); len(problems) > 0 {
		t.Errorf("event still holds: %v", problems)
	}
	client := e["client"].(map[string]any)
	if client["ipAddress"] != "192.0.2.1" || client["device"] != "Computer" || e["eventType"] != "user.session.start" {
		t.Errorf("the scrub changed values the collector reads: %v", e)
	}

	o := scrub(org)
	if problems := unscrubbed(o, ""); len(problems) > 0 {
		t.Errorf("org still holds: %v", problems)
	}
	if o["subdomain"] != "acme" || o["status"] != "ACTIVE" {
		t.Errorf("the scrub changed values the collector reads: %v", o)
	}
}

// TestRecordingsScrubbed fails while a committed recording still holds a
// value recordScrubPatterns remove.
func TestRecordingsScrubbed(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "recordings", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, problem := range unscrubbed(doc, "") {
			t.Errorf("%s: %s", path, problem)
		}
	}
}

// unscrubbed lists each member under node that recordScrubPatterns would
// have replaced.
func unscrubbed(node any, at string) []string {
	var out []string
	switch n := node.(type) {
	case map[string]any:
		for key, value := range n {
			here := at + "/" + key
			switch key {
			case "geographicalContext", "securityContext", "ipDetails", "debugContext":
				if value != nil {
					out = append(out, here+" is not null")
				}
				continue
			case "device":
				if _, ok := value.(map[string]any); ok {
					out = append(out, here+" is an object")
					continue
				}
			case "userAgent":
				var want any
				_ = json.Unmarshal([]byte(recordedUserAgent), &want)
				if value != nil && !reflect.DeepEqual(value, want) {
					out = append(out, here+" is not the placeholder user agent")
				}
				continue
			case "companyName":
				if value != nil && value != "Example" {
					out = append(out, here+" is not the placeholder name")
				}
			case "website":
				if value != nil && value != "https://example.com" {
					out = append(out, here+" is not the placeholder website")
				}
			case "address1", "address2", "city", "state", "postalCode", "phoneNumber", "supportPhoneNumber", "endUserSupportHelpURL":
				if value != nil {
					out = append(out, here+" is not null")
				}
			}
			out = append(out, unscrubbed(value, here)...)
		}
	case []any:
		for i, v := range n {
			out = append(out, unscrubbed(v, fmt.Sprintf("%s/%d", at, i))...)
		}
	}
	return out
}

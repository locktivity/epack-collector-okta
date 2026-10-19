// Package schema embeds the JSON Schemas of the collector's artifacts.
package schema

import _ "embed"

//go:embed v1.0.0.json
var detailed []byte

// Schemas maps each artifact path to its JSON Schema, for
// componentsdk.CollectorSpec.Schemas. The normalized idp-posture artifact is
// checked against the SDK's own schema for its type.
func Schemas() map[string][]byte {
	return map[string][]byte{"artifacts/okta.json": detailed}
}

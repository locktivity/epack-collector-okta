// Package schema embeds the JSON Schemas of the collector's artifacts and
// its trace map.
package schema

import _ "embed"

//go:embed v1.0.0.json
var detailed []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Schemas maps each artifact path to its JSON Schema, for
// componentsdk.CollectorSpec.Schemas. The normalized idp-posture artifact is
// checked against the SDK's own schema for its type.
func Schemas() map[string][]byte {
	return map[string][]byte{"artifacts/okta.json": detailed}
}

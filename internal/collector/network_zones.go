package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// NetworkZones is the network-zones surface. Collected at audit and above; trust
// omits it.
//
// Audit: counts by type + gateway / proxy zone counts + per-zone summary.
// Internal: + per-zone CIDR / gateway-IP / proxy-IP / location / ASN definitions.
type NetworkZones struct {
	TotalCount       int            `json:"total_count"`
	CountByType      map[string]int `json:"count_by_type"`
	GatewayZoneCount *int           `json:"gateway_zone_count"`
	ProxyZoneCount   *int           `json:"proxy_zone_count"`

	Inventory []NetworkZoneSummary `json:"inventory,omitempty"`
}

// NetworkZoneSummary is a per-zone row (audit+). Internal adds the definitions.
type NetworkZoneSummary struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
	Usage  string `json:"usage"`

	// Internal-level fields.
	Gateways  []string `json:"gateways,omitempty"`
	Proxies   []string `json:"proxies,omitempty"`
	Locations []string `json:"locations,omitempty"`
	ASNs      []string `json:"asns,omitempty"`
}

// zoneTally counts the zones with a populated field, and the zones whose
// field could not be decoded.
type zoneTally struct {
	populated, unreadable int
	firstErr              error
}

func (t *zoneTally) observe(values []string, err error) {
	switch {
	case err != nil:
		t.unreadable++
		if t.firstErr == nil {
			t.firstErr = err
		}
	case len(values) > 0:
		t.populated++
	}
}

func (c *Collector) collectNetworkZones(ctx context.Context, level componentsdk.Level) *NetworkZones {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}
	zones, err := c.client.ListNetworkZones(ctx)
	if err != nil {
		err = c.warnSurface("network zones", "okta.networkZones.read", err)
		c.gaps.notCollected(err, "/network_zones")
		return nil
	}

	out := &NetworkZones{
		TotalCount:  len(zones),
		CountByType: make(map[string]int),
	}
	internal := level.AtLeast(componentsdk.LevelInternal)
	var gatewayZones, proxyZones zoneTally
	out.Inventory = make([]NetworkZoneSummary, 0, len(zones))
	for i, z := range zones {
		out.CountByType[z.Type]++

		// Parsed once per zone; reused for both the counts and the internal rows.
		gateways, gatewaysErr := c.zoneAddresses(z.Name, "gateways", z.Gateways)
		proxies, proxiesErr := c.zoneAddresses(z.Name, "proxies", z.Proxies)
		gatewayZones.observe(gateways, gatewaysErr)
		proxyZones.observe(proxies, proxiesErr)

		row := NetworkZoneSummary{ID: z.ID, Name: z.Name, Type: z.Type, Status: z.Status, Usage: z.Usage}
		if internal {
			row.Gateways = gateways
			row.Proxies = proxies
			locations, locationsErr := c.zoneLocations(z.Name, z.Type, z.Locations)
			asns, asnsErr := c.zoneASNs(z.Name, z.Type, z.Asns)
			row.Locations = locations
			row.ASNs = asns
			for _, field := range []struct {
				name string
				err  error
			}{{"gateways", gatewaysErr}, {"proxies", proxiesErr}, {"locations", locationsErr}, {"asns", asnsErr}} {
				if field.err != nil {
					c.gaps.notCollected(field.err, rowPointer("/network_zones/inventory", i, field.name))
				}
			}
		}
		out.Inventory = append(out.Inventory, row)
	}

	if gatewayZones.unreadable > 0 {
		c.gaps.partial(gatewayZones.unreadable, gatewayZones.firstErr, "/network_zones/gateway_zone_count")
	} else {
		out.GatewayZoneCount = intPtr(gatewayZones.populated)
	}
	if proxyZones.unreadable > 0 {
		c.gaps.partial(proxyZones.unreadable, proxyZones.firstErr, "/network_zones/proxy_zone_count")
	} else {
		out.ProxyZoneCount = intPtr(proxyZones.populated)
	}

	return out
}

// emptyZoneField reports whether a zone field is an empty / absent representation
// (Okta uses {} for an empty field on some zone types). These never warn; only a
// populated but unparseable shape does.
func emptyZoneField(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "[]", "{}":
		return true
	default:
		return false
	}
}

// unexpectedZoneShape warns about a zone field that is populated but cannot be
// decoded, and returns the error its gap carries, so silent data loss is
// visible rather than masquerading as "empty".
func (c *Collector) unexpectedZoneShape(zone, field string) error {
	warning := c.warn("network zones: zone %q %s: unexpected shape, skipped", zone, field)
	return failed(componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("network zone %q has %s in an unexpected shape", zone, field)), warning, "")
}

// zoneAddresses decodes a zone's gateways/proxies raw JSON (an array of
// {type, value}).
func (c *Collector) zoneAddresses(zone, field string, raw json.RawMessage) ([]string, error) {
	if emptyZoneField(raw) {
		return nil, nil
	}
	var addrs []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &addrs); err != nil {
		return nil, c.unexpectedZoneShape(zone, field)
	}
	values := make([]string, 0, len(addrs))
	for _, a := range addrs {
		values = append(values, a.Value)
	}
	return values, nil
}

// zoneTypeEnhancedDynamic is Okta's enhanced dynamic zone. It holds its
// locations and ASNs as include and exclude lists. A DYNAMIC zone holds them
// as arrays.
const zoneTypeEnhancedDynamic = "DYNAMIC_V2"

// decodeZoneList decodes a zone's locations or asns. It returns the items a
// DYNAMIC zone's array holds, or a DYNAMIC_V2 zone's include and exclude
// lists.
func decodeZoneList[T any](zoneType string, raw json.RawMessage) (include, exclude []T, err error) {
	if zoneType != zoneTypeEnhancedDynamic {
		err = json.Unmarshal(raw, &include)
		return include, nil, err
	}
	var lists struct {
		Include []T `json:"include"`
		Exclude []T `json:"exclude"`
	}
	err = json.Unmarshal(raw, &lists)
	return lists.Include, lists.Exclude, err
}

// excludedZoneValues warns about a DYNAMIC_V2 zone that excludes locations or
// ASNs, and returns the error its gap carries. An inventory row holds only the
// values a zone matches, and has no field for excluded ones.
func (c *Collector) excludedZoneValues(zone, field string) error {
	warning := c.warn("network zones: zone %q %s: has excluded values, skipped", zone, field)
	return failed(componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("network zone %q excludes %s, and the inventory row has no field for excluded values", zone, field)), warning, "")
}

// zoneLocations decodes a zone's locations raw JSON (an array of {country,
// region}, or for DYNAMIC_V2 the include list of them).
func (c *Collector) zoneLocations(zone, zoneType string, raw json.RawMessage) ([]string, error) {
	if emptyZoneField(raw) {
		return nil, nil
	}
	locs, excluded, err := decodeZoneList[struct {
		Country string `json:"country"`
		Region  string `json:"region"`
	}](zoneType, raw)
	if err != nil {
		return nil, c.unexpectedZoneShape(zone, "locations")
	}
	if len(excluded) > 0 {
		return nil, c.excludedZoneValues(zone, "locations")
	}
	// Okta's region value already starts with the country code, as in US-CA.
	values := make([]string, 0, len(locs))
	for _, l := range locs {
		if l.Region != "" {
			values = append(values, l.Region)
		} else {
			values = append(values, l.Country)
		}
	}
	return values, nil
}

// zoneASNs decodes a zone's asns raw JSON (an array of strings, or for
// DYNAMIC_V2 the include list of them).
func (c *Collector) zoneASNs(zone, zoneType string, raw json.RawMessage) ([]string, error) {
	if emptyZoneField(raw) {
		return nil, nil
	}
	asns, excluded, err := decodeZoneList[string](zoneType, raw)
	if err != nil {
		return nil, c.unexpectedZoneShape(zone, "asns")
	}
	if len(excluded) > 0 {
		return nil, c.excludedZoneValues(zone, "asns")
	}
	return asns, nil
}

package collector

import (
	"context"
	"encoding/json"
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
	GatewayZoneCount int            `json:"gateway_zone_count"`
	ProxyZoneCount   int            `json:"proxy_zone_count"`

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

func (c *Collector) collectNetworkZones(ctx context.Context, level componentsdk.Level) *NetworkZones {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}
	c.status("Collecting network zones...")

	zones, err := c.client.ListNetworkZones(ctx)
	if err != nil {
		c.warnSurface("network zones", "okta.networkZones.read", err)
		return nil
	}

	out := &NetworkZones{
		TotalCount:  len(zones),
		CountByType: make(map[string]int),
	}
	internal := level.AtLeast(componentsdk.LevelInternal)
	out.Inventory = make([]NetworkZoneSummary, 0, len(zones))
	for _, z := range zones {
		out.CountByType[z.Type]++

		// Parsed once per zone; reused for both the counts and the internal rows.
		gateways := c.zoneAddresses(z.Name, "gateways", z.Gateways)
		proxies := c.zoneAddresses(z.Name, "proxies", z.Proxies)
		if len(gateways) > 0 {
			out.GatewayZoneCount++
		}
		if len(proxies) > 0 {
			out.ProxyZoneCount++
		}

		row := NetworkZoneSummary{ID: z.ID, Name: z.Name, Type: z.Type, Status: z.Status, Usage: z.Usage}
		if internal {
			row.Gateways = gateways
			row.Proxies = proxies
			row.Locations = c.zoneLocations(z.Name, z.Locations)
			row.ASNs = c.zoneASNs(z.Name, z.Asns)
		}
		out.Inventory = append(out.Inventory, row)
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

// zoneAddresses decodes a zone's gateways/proxies raw JSON (an array of
// {type, value}). A populated but unexpected shape is skipped with a diagnostic,
// so silent data loss is visible rather than masquerading as "empty".
func (c *Collector) zoneAddresses(zone, field string, raw json.RawMessage) []string {
	if emptyZoneField(raw) {
		return nil
	}
	var addrs []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &addrs); err != nil {
		c.warn("network zones: zone %q %s: unexpected shape, skipped", zone, field)
		return nil
	}
	values := make([]string, 0, len(addrs))
	for _, a := range addrs {
		values = append(values, a.Value)
	}
	return values
}

// zoneLocations decodes a zone's locations raw JSON (an array of {country, region}).
func (c *Collector) zoneLocations(zone string, raw json.RawMessage) []string {
	if emptyZoneField(raw) {
		return nil
	}
	var locs []struct {
		Country string `json:"country"`
		Region  string `json:"region"`
	}
	if err := json.Unmarshal(raw, &locs); err != nil {
		c.warn("network zones: zone %q locations: unexpected shape, skipped", zone)
		return nil
	}
	values := make([]string, 0, len(locs))
	for _, l := range locs {
		if l.Region != "" {
			values = append(values, l.Country+"-"+l.Region)
		} else {
			values = append(values, l.Country)
		}
	}
	return values
}

// zoneASNs decodes a zone's asns raw JSON (an array of strings).
func (c *Collector) zoneASNs(zone string, raw json.RawMessage) []string {
	if emptyZoneField(raw) {
		return nil
	}
	var asns []string
	if err := json.Unmarshal(raw, &asns); err != nil {
		c.warn("network zones: zone %q asns: unexpected shape, skipped", zone)
		return nil
	}
	return asns
}

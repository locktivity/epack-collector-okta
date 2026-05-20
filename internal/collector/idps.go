package collector

import (
	"context"
	"net/url"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// IdentityProviders is the federation-IdP surface.
//
// Collected at audit and above; trust omits it.
//
// Audit: count by protocol + per-IdP name + type + status + issuer host (host only).
// Internal: + signing-cert thumbprint (kid), JIT-provisioning flag, group-mapping
// count.
//
// Hard rule: client secrets, signing keys, and full SSO URLs are never emitted.
// Only the issuer host and the cert thumbprint (an identifier, not key material)
// are surfaced.
type IdentityProviders struct {
	TotalCount      int            `json:"total_count"`
	CountByProtocol map[string]int `json:"count_by_protocol"`

	Inventory []IdPSummary `json:"inventory,omitempty"`
}

// IdPSummary is a per-IdP row (audit+).
type IdPSummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	IssuerHost string `json:"issuer_host,omitempty"`

	// Internal-level fields.
	SigningCertThumbprint string `json:"signing_cert_thumbprint,omitempty"`
	JITProvisioning       *bool  `json:"jit_provisioning,omitempty"`
	GroupMappingCount     *int   `json:"group_mapping_count,omitempty"`
}

func (c *Collector) collectIdentityProviders(ctx context.Context, level componentsdk.Level) *IdentityProviders {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return nil
	}
	c.status("Collecting identity providers...")

	idps, err := c.client.ListIdentityProviders(ctx)
	if err != nil {
		c.warnSurface("identity providers", "okta.idps.read", err)
		return nil
	}

	out := &IdentityProviders{
		TotalCount:      len(idps),
		CountByProtocol: make(map[string]int),
	}
	for _, idp := range idps {
		out.CountByProtocol[idp.Type]++
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out
	}

	out.Inventory = make([]IdPSummary, 0, len(idps))
	for _, idp := range idps {
		row := IdPSummary{
			ID:         idp.ID,
			Name:       idp.Name,
			Type:       idp.Type,
			Status:     idp.Status,
			IssuerHost: hostOnly(idp.Protocol.Credentials.Trust.Issuer),
		}
		if level.AtLeast(componentsdk.LevelInternal) {
			row.SigningCertThumbprint = idp.Protocol.Credentials.Trust.Kid
			jit := strings.EqualFold(idp.Policy.Provisioning.Action, "AUTO")
			row.JITProvisioning = &jit
			count := len(idp.Policy.Provisioning.Groups.Assignments)
			row.GroupMappingCount = &count
		}
		out.Inventory = append(out.Inventory, row)
	}

	return out
}

// hostOnly returns the host of a URL or URN, never the full value (which can
// embed tokens). Returns "" if no host can be parsed.
func hostOnly(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

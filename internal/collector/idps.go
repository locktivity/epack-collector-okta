package collector

import (
	"context"
	"net/url"
	"strings"

	"github.com/locktivity/epack-collector-okta/internal/okta"
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
	idps, err := c.client.ListIdentityProviders(ctx)
	if err != nil {
		err = c.warnSurface("identity providers", "okta.idps.read", err)
		c.gaps.notCollected(err, "/identity_providers")
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
			IssuerHost: issuerHost(idp),
		}
		if level.AtLeast(componentsdk.LevelInternal) {
			row.SigningCertThumbprint = idp.Protocol.Credentials.Trust.Kid
			jit := strings.EqualFold(idp.Policy.Provisioning.Action, "AUTO")
			row.JITProvisioning = &jit
			count := groupMappingCount(idp)
			row.GroupMappingCount = &count
		}
		out.Inventory = append(out.Inventory, row)
	}

	return out
}

// groupMappingCount counts the groups an IdP can add the people it
// provisions to. Okta uses assignments for the ASSIGN action, and the filter
// allowlist for APPEND and SYNC.
func groupMappingCount(idp okta.IdentityProvider) int {
	groups := idp.Policy.Provisioning.Groups
	switch strings.ToUpper(groups.Action) {
	case "APPEND", "SYNC":
		return len(groups.Filter)
	}
	return len(groups.Assignments)
}

// issuerHost returns the host of the IdP's issuer. A SAML issuer is in
// protocol.credentials.trust.issuer. An OpenID Connect issuer, as for Google
// or Microsoft, is in protocol.issuer.url.
func issuerHost(idp okta.IdentityProvider) string {
	if host := hostOnly(idp.Protocol.Credentials.Trust.Issuer); host != "" {
		return host
	}
	return hostOnly(idp.Protocol.Issuer.URL)
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

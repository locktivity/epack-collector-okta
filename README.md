# epack-collector-okta

Okta organization security posture collector for [epack](https://github.com/locktivity/epack).

## Overview

This collector gathers security posture metrics from an Okta organization, including:

- **Posture**: MFA coverage, phishing-resistant MFA, SSO coverage
- **Users**: Account health (expired passwords, lockouts, inactive and suspended accounts)
- **Apps**: Provisioning and deprovisioning automation
- **Privileged Access**: Admin role coverage, super admins, and privileged MFA strength
- **Policy**: MFA coverage evaluation, session settings
- **Device access**: Managed-device enforcement and device-assurance policies
- **Groups, network zones, identity providers, hooks, API tokens, org settings, and a security-relevant system-log slice** (surfaced at `audit` / `internal`)

## Collection levels

The collector supports three cumulative levels, selected by the `level` key in
`epack.yaml`. Each higher level is a strict superset of the one below it.

- **trust** (default): org-level aggregates only (counts, percentages, on/off flags). No user logins, app names, policy details, or system-log events. Matches the collector's long-standing output.
- **audit**: adds per-entity detail for an auditor: user / app / group / network-zone / IdP / hook / API-token inventories, per-policy and per-admin summaries, and 7-day counts of security-relevant system-log events. Login is the only user identifier; profile attributes beyond login are excluded.
- **internal**: adds the rawest data for ongoing internal monitoring and review: per-user factor lists and activity timestamps, group member logins, per-policy rule conditions and actions, network-zone and IdP definitions, and the security-relevant system-log event slice.

User profile attributes beyond login, password hashes, session tokens, IdP
signing keys / client secrets, hook authentication headers, and full hook / SSO
URLs are **never** emitted at any level. See [docs/levels.md](docs/levels.md)
for the full per-surface, per-level breakdown.

For very large orgs, internal-level inventories are capped (50,000 users, 5,000
apps, 10,000 groups, 200,000 total group-membership rows, 5,000 system-log
events); a `*_truncated` flag and dropped-row count mark any cap that fires.
Recommend `--timeout 30m` for orgs over 10,000 users at `internal`.

```yaml
collectors:
  okta:
    source: locktivity/epack-collector-okta@^0.2
    level: audit   # trust | audit | internal
    config:
      org_domain: company.okta.com
```

## Installation

```bash
go install github.com/locktivity/epack-collector-okta/cmd/epack-collector-okta@latest
```

Or build from source:

```bash
make build
```

## Configuration

### epack.yaml

```yaml
collectors:
  okta:
    source: locktivity/epack-collector-okta@^0.2
    level: trust                           # trust | audit | internal
    config:
      org_domain: company.okta.com
      client_id: 0oa1234567890abcdef
      key_id: abc123xyz                    # From Okta public key settings
    secrets:
      - OKTA_PRIVATE_KEY
```

### Authentication

#### OAuth 2.0 (Recommended)

1. Create an OAuth 2.0 service app in Okta Admin Console
2. Configure public key authentication and generate a key pair
3. Uncheck **Require Demonstrating Proof of Possession (DPoP)**
4. Download the private key in **PEM format** (not JWK/JSON)
5. Copy the **Key ID** from the public key settings (General → Client Credentials → Public Keys)
6. Grant the API scopes for the levels you intend to run (see [Required OAuth scopes](#required-oauth-scopes))
7. Assign **Read Only Administrator** role to the service app (Security → Administrators). The API-token surface at `audit` / `internal` additionally requires a **Super Administrator**-equivalent role.
8. Set `OKTA_PRIVATE_KEY` environment variable:
   ```bash
   export OKTA_PRIVATE_KEY="$(cat ~/.okta/epack-private-key.pem)"
   ```

### Required OAuth scopes

The collector requests the scopes for the level it runs at; each level includes
the scopes of the levels below it. A scope the service app has not been granted
is dropped from the issued token, and the values that need it are then left out,
with a gap in the collector result and a `diagnostics.warnings` entry. Grant the
scopes for your level **before** running to collect every surface.

| Scope | Levels | Surface |
|---|---|---|
| `okta.users.read` | trust+ | Users, posture, privileged access, policy coverage |
| `okta.groups.read` | trust+ | Group resolution, groups surface |
| `okta.apps.read` | trust+ | Apps |
| `okta.policies.read` | trust+ | Policy; org settings' `self_service_recovery_enabled` (audit+) |
| `okta.roles.read` | trust+ | Privileged access (role assignments, custom roles); listing role assignments needs a Super Administrator-level role |
| `okta.deviceAssurance.read` | trust+ | Device access (requires the Device Assurance feature) |
| `okta.authenticators.read` | audit+ | Per-factor-type counts; per-user factor list (internal) |
| `okta.networkZones.read` | audit+ | Network zones |
| `okta.idps.read` | audit+ | Identity providers |
| `okta.eventHooks.read` | audit+ | Event hooks |
| `okta.inlineHooks.read` | audit+ | Inline hooks |
| `okta.logs.read` | audit+ | System log |
| `okta.orgs.read` | audit+ | Org settings |
| `okta.apiTokens.read` | audit+ | API tokens (also requires a Super Administrator-level role) |

When a scope is missing or a feature is not licensed (for example custom admin
roles without Okta Identity Governance), the affected values are left out rather
than failing the run (see [Partial collection and exit codes](#partial-collection-and-exit-codes)).

#### API Token (Legacy)

1. Create an API token in Okta Admin Console
2. Set `OKTA_API_TOKEN` environment variable

The SSWS API-token path is deprecated; prefer an OAuth 2.0 service app. With an
SSWS token, surface access is governed by the token owner's assigned admin role
rather than OAuth scopes: a **Read Only Administrator** covers most surfaces at
`trust` and `audit`, while the API-token and admin-role inventories at `audit` /
`internal` require a **Super Administrator**-equivalent role. Migrate to an OAuth
service app to use the scope-based model above.

## Output Schema

See [docs/schema/v1.0.0.json](docs/schema/v1.0.0.json) for the full JSON schema.

### Partial collection and exit codes

The run fails only when the configuration is invalid or the sign-in fails. The
sign-in proves the credential before any surface is read: an API token reads the
user it belongs to (`GET /api/v1/users/me`), and a service app exchanges its
signed assertion at the org's token endpoint.

| Exit | Code | When |
|---|---|---|
| 0 | | The run collected, even if some values were left out |
| 1 | `invalid_response` | The sign-in response was not what the collector expects |
| 2 | `config_invalid` | `org_domain` or the credentials are missing, `OKTA_PRIVATE_KEY` is not a PEM-encoded RSA key, or the token endpoint answered `invalid_request` or `unsupported_grant_type` |
| 3 | `auth_failed` | Okta rejected the API token or the service app's assertion |
| 3 | `permission_denied` | Okta refused a requested OAuth scope at the token exchange |
| 4 | `rate_limited`, `vendor_error`, `timeout` | The sign-in could not reach Okta |

After the sign-in, a value the collector cannot read is left out rather than
written as 0, false, or an empty list: a top-level metric is `null`, and an
inventory or a whole surface is absent. The artifact
`artifacts/okta.collector-result.json` lists a gap for each value left out, with
a code such as `permission_denied`, `rate_limited`, or `not_licensed`, along with
the API operations the collector called and the identity it signed in as. The
`diagnostics.warnings` entries remain. A percentage is also `null` when its
population is empty, such as `mfa_coverage` in an org with no users;
`users.total_count` and `apps.total_count` give those populations.

### Example Output

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-02-25T14:00:00Z",
  "collected_at_level": "trust",
  "org_domain": "company.okta.com",
  "posture": {
    "mfa_coverage": 85,
    "mfa_phishing_resistant": 20,
    "sso_coverage": 90
  },
  "users": {
    "total_count": 412,
    "password_expired": 2,
    "locked_out": 0,
    "inactive": 15,
    "suspended": 3
  },
  "apps": {
    "total_count": 37,
    "provisioning_enabled": 40,
    "deprovisioning_enabled": 30
  },
  "privileged_access": {
    "privileged_users_count": 6,
    "super_admin_count": 2,
    "standing_privileged_users_count": 6,
    "privileged_mfa_coverage_pct": 100,
    "privileged_phishing_resistant_pct": 50
  },
  "policy": {
    "policy_count": 2,
    "mfa_required_all": false,
    "mfa_required_any": true,
    "mfa_required_coverage_pct": 33,
    "session_lifetime_min_minutes": 15,
    "session_lifetime_max_minutes": 1440,
    "idle_timeout_min_minutes": 5,
    "idle_timeout_max_minutes": 120
  }
}
```

## Development

### Build

```bash
make build
```

### Test

```bash
make test
```

### SDK Conformance Test

```bash
make sdk-test
```

### End-to-End Tests

E2E tests make real API requests to Okta. They are excluded from normal test runs via a build tag and require environment variables:

```bash
# Set required environment variable
export OKTA_ORG_DOMAIN=dev-12345.okta.com

# OAuth 2.0 authentication (recommended)
export OKTA_CLIENT_ID=0oa1234567890abcdef
export OKTA_KEY_ID=abc123xyz
export OKTA_PRIVATE_KEY="$(cat ~/.okta/epack-private-key.pem)"

# Or API token authentication (legacy)
export OKTA_API_TOKEN=00abc123...

# Run e2e tests
go test -v -tags=e2e ./internal/collector/...
```

The E2E tests validate:
- Basic collection works with real Okta data
- All percentage metrics are in valid 0-100 range
- Policy settings are properly captured
- Output JSON structure matches expected schema

## License

Apache-2.0

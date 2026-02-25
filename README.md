# epack-collector-okta

Okta organization security posture collector for [epack](https://github.com/locktivity/epack).

## Overview

This collector gathers security posture metrics from an Okta organization, including:

- **Posture**: MFA coverage, phishing-resistant MFA, SSO coverage
- **Users**: Account health (expired passwords, lockouts, inactive accounts)
- **Apps**: Provisioning and deprovisioning automation
- **Policy**: MFA requirements, session settings

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
    source: locktivity/epack-collector-okta@^0.1
    config:
      org_domain: company.okta.com
      client_id: 0oa1234567890abcdef
    secrets:
      - OKTA_PRIVATE_KEY
```

### Authentication

#### OAuth 2.0 (Recommended)

1. Create an OAuth 2.0 service app in Okta Admin Console
2. Configure public key authentication and generate a key pair
3. Download the private key in **PEM format** (not JWK/JSON)
4. Grant API scopes: `okta.users.read`, `okta.apps.read`, `okta.policies.read`
5. Assign **Read Only Administrator** role to the service app (Security → Administrators)
6. Set `OKTA_PRIVATE_KEY` environment variable:
   ```bash
   export OKTA_PRIVATE_KEY="$(cat ~/.okta/epack-private-key.pem)"
   ```

#### API Token (Legacy)

1. Create an API token in Okta Admin Console
2. Set `OKTA_API_TOKEN` environment variable

## Output Schema

See [docs/schema/v1.0.0.json](docs/schema/v1.0.0.json) for the full JSON schema.

### Example Output

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-02-25T14:00:00Z",
  "org_domain": "company.okta.com",
  "posture": {
    "mfa_coverage": 85,
    "mfa_phishing_resistant": 20,
    "sso_coverage": 90
  },
  "users": {
    "password_expired": 2,
    "locked_out": 0,
    "inactive": 15
  },
  "apps": {
    "provisioning_enabled": 40,
    "deprovisioning_enabled": 30
  },
  "policy": {
    "policy_count": 2,
    "mfa_required_all": false,
    "mfa_required_any": true,
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

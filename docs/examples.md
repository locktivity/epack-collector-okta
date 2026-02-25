# Examples

## Basic Usage

### Using OAuth 2.0 (Recommended)

```yaml
stream: myorg/okta-posture

collectors:
  okta:
    source: locktivity/epack-collector-okta@^0.1
    config:
      org_domain: company.okta.com
      client_id: 0oa1234567890abcdef
    secrets:
      - OKTA_PRIVATE_KEY
```

Then run:

```bash
export OKTA_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
epack collect
```

See [Configuration](configuration.md) for OAuth 2.0 setup instructions.

### Using API Token (Legacy)

```yaml
stream: myorg/okta-posture

collectors:
  okta:
    source: locktivity/epack-collector-okta@^0.1
    config:
      org_domain: company.okta.com
    secrets:
      - OKTA_API_TOKEN
```

Then run:

```bash
export OKTA_API_TOKEN=00abcdef...
epack collect
```

## Sample Output

```json
{
  "protocol_version": 1,
  "data": {
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
}
```

All coverage values are percentages (0-100). See [Overview](overview.md) for detailed metric descriptions.

## CI/CD Integration

### GitHub Actions (with OAuth 2.0)

```yaml
name: Collect Evidence

on:
  schedule:
    - cron: "0 0 * * 1"  # Weekly on Monday
  workflow_dispatch:

jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install epack
        run: |
          curl -sSL https://github.com/locktivity/epack/releases/latest/download/epack-linux-amd64 -o epack
          chmod +x epack
          sudo mv epack /usr/local/bin/

      - name: Collect evidence
        run: epack collect --frozen
        env:
          OKTA_PRIVATE_KEY: ${{ secrets.OKTA_PRIVATE_KEY }}

      - name: Upload pack
        uses: actions/upload-artifact@v4
        with:
          name: evidence-pack
          path: "*.pack"
```

Store the Okta private key as a repository secret named `OKTA_PRIVATE_KEY`.

## Multiple Okta Organizations

To collect from multiple Okta orgs, define separate collectors:

```yaml
stream: mycompany/identity-posture

collectors:
  okta-prod:
    source: locktivity/epack-collector-okta@^0.1
    config:
      org_domain: company.okta.com
      client_id: 0oa1234567890abcdef
    secrets:
      - OKTA_PROD_PRIVATE_KEY

  okta-preview:
    source: locktivity/epack-collector-okta@^0.1
    config:
      org_domain: company.oktapreview.com
      client_id: 0oa0987654321fedcba
    secrets:
      - OKTA_PREVIEW_PRIVATE_KEY
```

Then set both environment variables:

```bash
export OKTA_PROD_PRIVATE_KEY="$(cat prod-key.pem)"
export OKTA_PREVIEW_PRIVATE_KEY="$(cat preview-key.pem)"
epack collect
```

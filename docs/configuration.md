# Okta Collector Configuration

## Authentication Setup

### OAuth 2.0 (Recommended)

OAuth 2.0 with private key JWT is the recommended authentication method. It provides:
- Scoped access (only the permissions you need)
- Short-lived tokens
- Better audit logging

#### Step 1: Create a Service App

1. Go to Okta Admin Console → Applications → Applications
2. Click "Create App Integration"
3. Select "API Services" and click Next
4. Name your application (e.g., "epack-collector")
5. Click Save

#### Step 2: Configure Public Key

1. In the app settings, go to "Client Credentials"
2. Edit the "Client authentication" section
3. Select "Public key / Private key"
4. **Disable DPoP**: Uncheck "Require Demonstrating Proof of Possession (DPoP) header in token requests"
5. In the "Public keys" section below, click "Edit"
6. Keep "Save keys in Okta" selected
7. Click "Generate new key"
8. **Important**: When prompted, choose **PEM** format (not JWK/JSON)
9. Download the private key immediately - Okta only shows it once
10. Save the private key securely (e.g., `~/.okta/epack-private-key.pem`)
11. **Copy the Key ID**: After saving, expand the key details to find the Key ID (a string like `abc123xyz...`). You'll need this for your epack config.

#### Step 3: Grant API Scopes

1. Go to the **Okta API Scopes** tab
The scopes you need depend on the collection [level](levels.md). A scope you
don't grant isn't fatal: the values that need it are left out, with a gap in the
collector result and a `diagnostics.warnings` entry, rather than failing the run.

2. Click **Grant** next to each scope you need:

   **Trust level (the default):**
   - `okta.users.read`
   - `okta.groups.read`
   - `okta.apps.read`
   - `okta.policies.read`
   - `okta.roles.read`
   - `okta.deviceAssurance.read` (device-access surface; needs the Device Assurance feature)

   **Audit and internal additionally need:** `okta.authenticators.read`,
   `okta.networkZones.read`, `okta.idps.read`, `okta.eventHooks.read`,
   `okta.inlineHooks.read`, `okta.logs.read`, `okta.orgs.read`,
   `okta.apiTokens.read`.

#### Step 4: Assign Admin Role

OAuth scopes alone aren't enough - the service app needs an admin role to access org-wide resources.

1. Go to **Security → Administrators**
2. Click **Add Administrator**
3. In the "Admin" field, search for and select your service app (e.g., "epack-collector")
4. Under "Role", select **Read Only Administrator** (assign it org-wide, not constrained to a resource set)
5. Click **Save Changes**

**Privileged-access note:** listing *who holds admin roles* is gated behind a
Super Administrator-level role; Read-Only Administrator cannot. With Read-Only
Admin, the `privileged_access` counts are left out with a `permission_denied`
gap and a diagnostic. Grant the app **Super Administrator** if you need
privileged-user counts; otherwise Read-Only Admin is sufficient for every other
surface.

#### Step 5: Configure epack

```yaml
collectors:
  okta:
    source: locktivity/epack-collector-okta@^0.2
    config:
      org_domain: your-org.okta.com
      client_id: 0oa1234567890abcdef   # From app settings
      key_id: abc123xyz                # From public key settings
      level: trust                     # trust (default) | audit | internal
    secrets:
      - OKTA_PRIVATE_KEY               # PEM-encoded private key
```

Set the environment variable (use the PEM file you downloaded):

```bash
export OKTA_PRIVATE_KEY="$(cat ~/.okta/epack-private-key.pem)"
```

### API Token (Legacy)

API tokens are simpler to set up but less secure:
- Tokens don't expire automatically
- Tokens have full permissions of the user who created them
- Harder to audit

#### Step 1: Create an API Token

1. Go to Okta Admin Console → Security → API → Tokens
2. Click "Create Token"
3. Name it (e.g., "epack-collector")
4. Copy the token value immediately (it won't be shown again)

#### Step 2: Configure epack

```yaml
collectors:
  okta:
    source: locktivity/epack-collector-okta@^0.2
    config:
      org_domain: your-org.okta.com
    secrets:
      - OKTA_API_TOKEN
```

Set the environment variable:

```bash
export OKTA_API_TOKEN="00abcdef..."
```

## Configuration Options

| Option | Required | Description |
|--------|----------|-------------|
| `org_domain` | Yes | Your Okta organization domain (e.g., `company.okta.com`) |
| `client_id` | For OAuth | OAuth 2.0 client ID from your service app |
| `key_id` | For OAuth | Key ID from the public key settings in your Okta app |
| `level` | No | Collection depth: `trust` (default), `audit`, or `internal`. See [levels.md](levels.md). Unrecognized values fall back to `trust`. |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OKTA_PRIVATE_KEY` | PEM-encoded RSA private key for OAuth 2.0 |
| `OKTA_API_TOKEN` | SSWS API token (legacy authentication) |

## Troubleshooting

### "Authentication required" error

Ensure either:
- `client_id`, `key_id` config and `OKTA_PRIVATE_KEY` env var are all set (for OAuth), OR
- `OKTA_API_TOKEN` env var is set (for API token auth)

### "Token exchange failed" or "invalid_client - JWT kid is invalid" error

The collector signs in before reading anything, so a rejected credential fails
the run with exit code 3 and the code `auth_failed`. For OAuth 2.0:
- Verify the `client_id` is correct
- Verify the `key_id` matches the Key ID shown in Okta (General → Client Credentials → Public Keys)
- Ensure the private key matches the public key configured in Okta (they're a matched pair)
- Make sure DPoP is disabled

(A missing OAuth scope does **not** fail the token exchange — Okta drops ungranted
scopes from the issued token, and the affected surface degrades; see "Missing
data" below.)

### "Rate limited" errors

When Okta throttles a read, the collector waits until the rate limit resets, as
the `X-Rate-Limit-Reset` header says, for at most a minute, and tries again.
Other failing reads are retried with exponential backoff. A read still throttled
after its retries is left out with a `rate_limited` gap. If you see persistent
rate limit gaps:
- Reduce collection frequency
- Contact Okta support to increase rate limits

### Missing data

When a surface can't be collected, the run still succeeds. Its values are left
out (`null` or absent, never zero), and the reason is recorded twice: as a gap
with a code in `artifacts/okta.collector-result.json`, and under
`diagnostics.warnings` in the output. Common causes:

- **Missing scope.** Each surface needs its scope granted for the level you're
  running (see [Step 3](#step-3-grant-api-scopes) and [levels.md](levels.md)).
- **`privileged_access` counts are null.** Listing admin-role assignments needs a
  Super Administrator-level role; Read-Only Admin can't (see the privileged-access
  note in [Step 4](#step-4-assign-admin-role)).
- **Device assurance values are null.** Needs `okta.deviceAssurance.read` and the
  Device Assurance feature.
- **A feature isn't licensed.** Custom admin roles need Okta Identity Governance;
  the custom-role inventory is left out with a `not_licensed` gap otherwise.
- **API token auth.** Access is governed by the token owner's admin role rather
  than scopes; ensure that role covers the surfaces you need.

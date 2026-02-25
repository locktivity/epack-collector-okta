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
4. In the "Public keys" section below, click "Edit"
5. Keep "Save keys in Okta" selected
6. Click "Generate new key"
7. **Important**: When prompted, choose **PEM** format (not JWK/JSON)
8. Download the private key immediately - Okta only shows it once
9. Save the private key securely (e.g., `~/.okta/epack-private-key.pem`)
10. **Disable DPoP**: In "General Settings", uncheck "Require Demonstrating Proof of Possession (DPoP) header in token requests" - this is redundant for server-side apps already using private key authentication

#### Step 3: Grant API Scopes

1. Go to the **Okta API Scopes** tab
2. Click **Grant** next to each of these scopes:
   - `okta.users.read`
   - `okta.apps.read`
   - `okta.policies.read`

#### Step 4: Assign Admin Role

OAuth scopes alone aren't enough - the service app needs an admin role to access org-wide resources.

1. Go to **Security → Administrators**
2. Click **Add Administrator**
3. In the "Admin" field, search for and select your service app (e.g., "epack-collector")
4. Under "Role", select **Read Only Administrator**
5. Click **Save Changes**

#### Step 4: Configure epack

```yaml
collectors:
  okta:
    source: locktivity/epack-collector-okta@^0.1
    config:
      org_domain: your-org.okta.com
      client_id: 0oa1234567890abcdef   # From app settings
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
    source: locktivity/epack-collector-okta@^0.1
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

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OKTA_PRIVATE_KEY` | PEM-encoded RSA private key for OAuth 2.0 |
| `OKTA_API_TOKEN` | SSWS API token (legacy authentication) |

## Troubleshooting

### "Authentication required" error

Ensure either:
- Both `client_id` config and `OKTA_PRIVATE_KEY` env var are set (for OAuth), OR
- `OKTA_API_TOKEN` env var is set (for API token auth)

### "Token exchange failed" error

For OAuth 2.0:
- Verify the client ID is correct
- Ensure the private key matches the public key configured in Okta
- Check that all required scopes are granted

### "Rate limited" errors

The collector handles rate limits automatically with exponential backoff. If you see persistent rate limit errors:
- Reduce collection frequency
- Contact Okta support to increase rate limits

### Missing data

Some metrics require specific permissions:
- Policy details require `okta.policies.read` scope
- If using API token, ensure the token creator has admin privileges

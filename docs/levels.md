# Collection Levels

The Okta collector accepts an optional `level` config knob controlling how much
detail it gathers. There are three levels, and they are cumulative: `internal`
is a strict superset of `audit`, which is a strict superset of `trust`. No level
removes a field that a lower level produced.

## The three levels

| Level | Question it answers | What's in the artifact |
|---|---|---|
| `trust` (default) | Do they pass? | Org-level aggregates and on/off flags only. No user logins, app names, policy details, or system-log events. |
| `audit` | Where is the gap? | Per-entity rows with identifying detail: user / app / group / network-zone / IdP / hook / API-token inventories, per-policy and per-admin summaries, and 7-day counts of security-relevant system-log events. Login is the only user identifier. |
| `internal` | Who or what specifically? | Per-user factor lists and activity timestamps, group member logins, per-policy rule conditions and actions, network-zone and IdP definitions, and the security-relevant system-log event slice. |

## Configuration

Set the level in your epack.yaml under the collector's `config` block:

```yaml
collectors:
  okta:
    source: locktivity/epack-collector-okta@^0.2
    level: audit
    config:
      org_domain: company.okta.com
      client_id: 0oa1234567890abcdef
      key_id: abc123xyz
    secrets:
      - OKTA_PRIVATE_KEY
```

Default is `trust` when the key is absent or empty. Unrecognized values (typos,
future levels we don't know about) downgrade to `trust` with a stderr warning;
the collector never silently upgrades to a higher level.

The active level appears in the output artifact as the top-level
`collected_at_level` field.

`audit` and `internal` require additional OAuth scopes beyond `trust`. See
[Required OAuth scopes](../README.md#required-oauth-scopes). When a scope is
missing or a feature is not licensed, the affected values are left out rather
than failing the run: the collector result records a gap for each, and
`diagnostics.warnings` says what to grant.

## What each level adds, per surface

### Posture (`posture`)

- **trust**: MFA coverage %, phishing-resistant MFA %, SSO coverage %.
- **audit**: `per_factor_type` (enrolled-user count per active factor type), `mfa_disabled_users_count`.

### Users (`users`)

- **trust**: password-expired / locked-out / inactive / suspended percentages.
- **audit**: `inventory[]` per-user rows (login, status, coarse Human/Service type, created-at).
- **internal**: each row gains last-login / last-updated / status-changed / password-changed timestamps, the enrolled-factor list, and group-membership IDs.

### Apps (`apps`)

- **trust**: provisioning / deprovisioning automation percentages.
- **audit**: `inventory[]` per-app rows (label, name, type, sign-on mode, status, SSO-configured, provisioning-configured).

### Privileged access (`privileged_access`)

- **trust**: privileged-user / super-admin / standing-privileged counts, privileged MFA + phishing-resistant coverage.
- **audit**: `inventory[]` per-privileged-user (login + assigned role names), `custom_roles[]` (custom admin roles; Okta Identity Governance feature, absent when not licensed).
- **internal**: each privileged-user row gains role-assignment source (direct / group / mixed) and last-login.

### Policy (`policy`)

- **trust**: active policy count, MFA-required flags + coverage %, session-lifetime and idle-timeout min/max.
- **audit**: `policies[]` per-policy summary (name, type, status, priority, rule count, scope summary) for sign-on and MFA-enroll policies.
- **internal**: each policy gains `rules[]` with conditions (network, groups, device) and actions (access, require-factor, session limits, enroll mode).

### Device access (`device_access`)

- **trust**: managed-device-required flags + coverage %, device-assurance-policy count.
- **audit**: `policies[]` per-device-assurance-policy summary (name, platform, status, min OS version, disk-encryption / screen-lock / jailbreak requirement flags).

The surfaces below are **not collected at trust** — they first appear at
`audit`. Their OAuth scopes are likewise only requested at `audit` and above, so
a trust run stays minimal.

### Groups (`groups`)

- **trust**: omitted.
- **audit**: total count, count by source, and `inventory[]` per-group rows (id, name, type, source, description, member count, created-at). The member count is Okta's group statistics.
- **internal**: each group gains `member_logins[]` (capped; see Truncation), and its member count becomes the number of members read, so the two agree. A group past the cap keeps the statistics.

### Network zones (`network_zones`)

- **trust**: omitted.
- **audit**: counts by type, gateway / proxy zone counts, and `inventory[]` per-zone rows (id, name, type, status, usage).
- **internal**: each zone gains gateway / proxy / location / ASN definitions.

### Identity providers (`identity_providers`)

- **trust**: omitted.
- **audit**: count by protocol and `inventory[]` per-IdP rows (id, name, type, status, issuer host — host only).
- **internal**: each IdP gains signing-cert thumbprint (kid), JIT-provisioning flag, group-mapping count.

### API tokens (`api_tokens`)

- **trust**: omitted.
- **audit**: active SSWS-token count, recently-used (30d) count, and `inventory[]` per-token rows (id, name, status, created-at).
- **internal**: each token gains created-by login, last-used, network-zone-scoped flag.

Reading API tokens requires a SUPER_ADMIN-level scope; on denial the surface is omitted with a gap and a diagnostic.

### Hooks (`hooks`)

- **trust**: omitted.
- **audit**: event-hook / inline-hook counts, active / inactive counts, and per-hook rows (name, type, status, subscribed events).
- **internal**: each hook gains endpoint host (host only) and channel type.

### System log (`system_log`)

- **trust**: omitted.
- **audit**: `count_by_category` of security-relevant events over the last 7 days.
- **internal**: `events[]` slice (event type, published, actor login + type, targets, outcome, client IP, user agent). Capped; see Truncation.

### Org settings (`org_settings`)

- **trust**: omitted.
- **audit**: subdomain, status, self-service-account-recovery flag.
- **internal**: system-notification contact logins.

## Artifact contract: what a missing value means

A field gated by level is absent below its level; `collected_at_level` records
the level that ran. At or above its level, a value the collector could not read
is left out too: a top-level metric is `null`, and an inventory or a whole
surface is absent. The collector result artifact,
`artifacts/okta.collector-result.json`, lists a gap for each value left out, so
"not collected" never reads as "none found". An inventory with no rows is also
absent; with no gap for it, none were found.

## Truncation

Internal-level inventories are capped for very large orgs to keep artifacts
within the per-collector size limit:

| Surface | Cap | Sort (most-significant kept) |
|---|---|---|
| Users | 50,000 | ACTIVE first, then login ascending |
| Apps | 5,000 | ACTIVE first, then label ascending |
| Groups | 10,000 groups | member count descending |
| Group memberships | 200,000 total member rows | largest groups first |
| System log | 5,000 events | published descending |

When a cap fires, the surface sets a `*_truncated` flag and a dropped-row count.
A group's member logins are emitted whole or not at all: once a group does not
fit, it and every smaller group have none. For orgs over 10,000 users, run
`internal` with `--timeout 30m`.

## Never emitted, at any level

User profile attributes beyond login (first / last name, phone, secondary email,
custom-schema values), password hashes, recovery-question answers, session
tokens, federation signing keys and client secrets, hook authentication headers
and secrets, full hook / SSO URLs, and system-log debug-context payloads are
never collected.

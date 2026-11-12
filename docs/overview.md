# Okta Collector Overview

The Okta collector gathers security posture metrics from your Okta organization.
At the default `trust` level these are org-level aggregates (percentages 0-100,
counts, and policy settings) designed to be actionable and comparable across
organizations. Higher [collection levels](levels.md) add per-entity detail and
additional surfaces (see [Collection levels](#collection-levels) below).

## Output Schema

The example below is `trust`-level output. The `collected_at_level` field records
the level a given artifact was produced at.

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-02-25T19:46:39Z",
  "collected_at_level": "trust",
  "org_domain": "company.okta.com",

  "posture": {
    "mfa_coverage": 87,
    "mfa_enrolled_users_count": 351,
    "mfa_phishing_resistant": 20,
    "mfa_phishing_resistant_users_count": 83,
    "sso_coverage": 89
  },

  "users": {
    "total_count": 412,
    "enabled_count": 399,
    "password_expired": 2,
    "password_expired_count": 9,
    "locked_out": 0,
    "locked_out_count": 1,
    "inactive": 15,
    "inactive_count": 62,
    "suspended": 3,
    "suspended_count": 13
  },

  "apps": {
    "total_count": 37,
    "sso_count": 33,
    "provisioning_enabled": 40,
    "provisioning_enabled_count": 15,
    "deprovisioning_enabled": 29,
    "deprovisioning_enabled_count": 11
  },

  "privileged_access": {
    "privileged_users_count": 6,
    "super_admin_count": 2,
    "standing_privileged_users_count": 6,
    "privileged_mfa_coverage_pct": 100,
    "privileged_mfa_enrolled_count": 6,
    "privileged_phishing_resistant_pct": 50,
    "privileged_phishing_resistant_count": 3
  },

  "policy": {
    "policy_count": 2,
    "mfa_required_all": false,
    "mfa_required_except_exclusions": false,
    "mfa_required_any": true,
    "mfa_required_coverage_pct": 34,
    "mfa_required_users_count": 136,
    "session_lifetime_min_minutes": 15,
    "session_lifetime_max_minutes": 1440,
    "idle_timeout_min_minutes": 5,
    "idle_timeout_max_minutes": 120
  },

  "device_access": {
    "managed_device_required": false,
    "managed_device_required_coverage_pct": 77,
    "managed_device_required_users_count": 309,
    "managed_device_required_for_admins": true,
    "managed_device_required_admins_count": 6,
    "device_assurance_policies_count": 3
  }
}
```

## Metrics Reference

A metric is `null` when the collector could not read what it needs, or when it
is a percentage of an empty population, such as MFA coverage in an org with no
users. The collector result artifact, `artifacts/okta.collector-result.json`,
records a gap for each value left out, with the reason.

Each percentage below, and each of `mfa_required_all`,
`managed_device_required` and `managed_device_required_for_admins`, has the
count it is computed from beside it, such as `mfa_enrolled_users_count` for `mfa_coverage` and `apps.sso_count`
for `sso_coverage`. Percentages are rounded down.

### posture

High-level security scores for quick assessment.

| Metric | Why It Matters |
|--------|----------------|
| `mfa_coverage` | **Account takeover protection.** MFA significantly reduces credential-based attacks. Low coverage leaves accounts vulnerable to password spraying and phishing. |
| `mfa_phishing_resistant` | **Strong authentication.** Phishing-resistant factors (WebAuthn/FIDO2, U2F, and Okta FastPass) can't be phished, unlike SMS or TOTP. This is the gold standard for sensitive accounts. |
| `sso_coverage` | **Credential sprawl reduction.** Apps not using SSO require separate passwords, increasing password fatigue and reuse risk. |

### users

User account health indicators.

| Metric | Why It Matters |
|--------|----------------|
| `total_count` | **Every account.** Users other than deprovisioned ones, in any status. `suspended` is a share of this count. |
| `enabled_count` | **Population.** Users whose account is enabled: `ACTIVE`, `PASSWORD_EXPIRED`, `LOCKED_OUT` or `RECOVERY`. Staged, provisioned and suspended accounts are left out. Every other user percentage, including the MFA and policy coverage figures, is a share of this count. |
| `password_expired` | **Compliance and access issues.** Users with expired passwords may be locked out or using workarounds that bypass security controls. |
| `locked_out` | **Potential attack indicator.** Spikes in lockout rates may indicate brute force or credential stuffing attacks. |
| `inactive` | **Orphan account risk.** Inactive accounts (90+ days no login) are prime targets for attackers. They may belong to departed employees or unused service accounts. |
| `suspended` | **Disabled account coverage.** Suspended accounts should usually represent intentionally blocked access. Tracking the rate helps distinguish active workforce posture from dormant or intentionally disabled identities. |

### apps

Application lifecycle management health.

| Metric | Why It Matters |
|--------|----------------|
| `total_count` | **Population.** Apps other than inactive ones, API service apps and Okta's own Admin Console, Dashboard and Browser Plugin apps. `sso_coverage` and the provisioning percentages are shares of this count. |
| `provisioning_enabled` | **Onboarding automation.** Manual provisioning delays access and increases admin burden. Automated provisioning ensures consistent access based on role. |
| `deprovisioning_enabled` | **Offboarding security.** Without automated deprovisioning, departing employees retain app access. This is a major source of data breaches. |

### privileged_access

Effective admin access across directly assigned and group-inherited role assignments.

| Metric | Why It Matters |
|--------|----------------|
| `privileged_users_count` | **Admin blast radius.** Counts people with an enabled account and an Okta admin role that can change who has access, reset credentials, or change sign-in settings. Read-Only and Report Administrators are left out, and so is a custom role whose permissions only read. This is the main denominator for privileged identity risk. |
| `super_admin_count` | **Highest-risk accounts.** Super admins can fully control the tenant. Keep this count as low as possible. |
| `standing_privileged_users_count` | **Always-on privilege.** In Okta, standard admin roles are effectively standing access unless additional JIT tooling is used outside the collector. |
| `privileged_mfa_coverage_pct` | **Privileged account protection.** Measures how many active admins have any MFA factor enrolled. |
| `privileged_phishing_resistant_pct` | **Strong admin auth.** Tracks phishing-resistant MFA coverage for privileged users, the highest-value identity target set. |

### policy

Aggregated security policy settings across the active sign-on policies. An MFA enrollment rule has people enroll once, so it does not count as requiring MFA.

| Metric | Why It Matters |
|--------|----------------|
| `policy_count` | **Policy complexity.** Number of active sign-on policies. More policies mean more nuanced access control but also more complexity to audit. |
| `mfa_required_all` | **Universal MFA enforcement.** True only if every sign-in of every enabled user must use MFA or is blocked, after policy evaluation. |
| `mfa_required_except_exclusions` | **MFA enforcement apart from named exceptions.** As `mfa_required_all`, setting aside the users and groups that policies and rules exclude by name, such as break-glass accounts. `policy.mfa_required` in `okta.idp-posture.json` is this value. |
| `mfa_required_any` | **Any MFA enforcement.** True if at least one enabled user is covered by an MFA requirement. |
| `mfa_required_coverage_pct` | **Actual MFA enforcement coverage.** Percentage of enabled users whose every sign-in must use MFA or is blocked, after evaluating policy and rule scope, including group targeting, network zones and managed-device conditions. |
| `session_lifetime_min_minutes` | **Strictest session policy.** The shortest session lifetime across active sign-on rules. Indicates your most restrictive access control. |
| `session_lifetime_max_minutes` | **Most permissive session.** The longest session lifetime across active sign-on rules. Users under this policy have extended access windows. |
| `idle_timeout_min_minutes` | **Strictest idle policy.** The shortest idle timeout across active sign-on rules. Protects high-risk users from unattended sessions. |
| `idle_timeout_max_minutes` | **Most permissive idle timeout.** The longest idle timeout across active sign-on rules. Users under this policy stay logged in longer when inactive. |

### Users who sign in through another identity provider

Okta's IdP routing rules can send a user's sign-ins to another identity provider, such as a partner's SAML provider or Google, and that provider decides whether the user uses MFA. The collector reads the routing rules with `okta.policies.read` at every level. A user they can send elsewhere, on any sign-in, signs in through that provider, and so does a user Okta holds no password for, whose credentials provider is `FEDERATION` or `SOCIAL`. Rules that send sign-ins to Okta itself, its desktop single sign-on (`IWA`, `AgentlessDSSO`) or its smart card provider (`X509`) don't count.

When an enabled user signs in through another provider, `okta.idp-posture.json` leaves out `user_security.mfa_user_count`, `phishing_resistant_user_count`, `mfa_coverage_pct` and `mfa_phishing_resistant_pct`, and `policy.mfa_required`, `mfa_required_user_count` and `mfa_required_coverage_pct`, with an `unsupported` gap. When an admin does, the `privileged_access` MFA values are left out the same way. At the `audit` level and above the gap names the providers, read from `/api/v1/idps`. When the routing rules can't be read, the same values are left out with the read's gap. `okta.details.json` still reports the factors users enrolled in Okta.

### device_access

Device access enforcement posture based on sign-on policy rule conditions.

| Metric | Why It Matters |
|--------|----------------|
| `managed_device_required` | **Device trust enforcement.** True if every enabled user can sign in from a managed device and every sign-in of theirs from another device is blocked. |
| `managed_device_required_coverage_pct` | **Device trust coverage.** Percentage of enabled users covered by a managed device requirement after evaluating policy and rule scope, including group targeting. |
| `managed_device_required_for_admins` | **Admin device trust.** True if all privileged users are covered by a managed device requirement. Critical for protecting high-value admin accounts from untrusted endpoints. |
| `device_assurance_policies_count` | **Device assurance policies.** Number of device assurance policies defined. These policies specify device requirements (OS version, encryption, etc.) that can be referenced in sign-on rules. |

## Collection levels

The surfaces above are the `trust` level. The `level` config knob (`trust` /
`audit` / `internal`) controls collection depth; levels are cumulative. See
[levels.md](levels.md) for the full per-surface, per-level breakdown.

- **trust** (default): the org-level aggregates documented above.
- **audit**: adds per-entity detail (user / app / group / network-zone / IdP /
  hook / API-token inventories, per-policy and per-admin summaries, and 7-day
  counts of security-relevant system-log events).
- **internal**: adds the rawest detail (per-user factor lists and activity
  timestamps, group member logins, per-policy rule conditions and actions,
  network-zone and IdP definitions, and the system-log event slice).

User profile attributes beyond login, passwords, session tokens, signing keys,
client secrets, and hook auth headers are never emitted at any level.

When a surface can't be collected (a missing scope, an unlicensed feature, or an
insufficient admin role), the run still succeeds. The values are left out rather
than reported as zero, the collector result artifact records a gap for each, and
a top-level `diagnostics.warnings` array says what to grant.

## Not Collected

Okta offers the following through its APIs, and the collector does not read them.

- **Devices.** The devices users enroll in Okta Verify, with each device's OS version and disk encryption. The collector writes no `endpoint-posture` file.
- **Service app credentials.** The client secrets and public keys of apps that call the Okta API with OAuth 2.0, and the Okta scopes granted to each app. From the `audit` level the collector reads API tokens only. It writes no `access-posture` file.
- **Access reviews.** Access certification campaigns and their reviews in Okta Identity Governance. The Identity Governance APIs require an Okta Identity Governance subscription.

## Use Cases

- **Security Baseline Assessment**: Get a quick snapshot of your Okta security posture
- **Compliance Monitoring**: Track MFA adoption, device trust, and policy enforcement over time
- **Risk Identification**: Find inactive accounts, privileged exposure, unmanaged device access, and apps lacking deprovisioning
- **Benchmark Comparison**: Compare posture across multiple Okta organizations

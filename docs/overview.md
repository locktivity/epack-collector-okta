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
    "mfa_coverage": 85,
    "mfa_enrolled_users_count": 351,
    "mfa_phishing_resistant": 20,
    "mfa_phishing_resistant_users_count": 83,
    "sso_coverage": 89
  },

  "users": {
    "total_count": 412,
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
    "mfa_required_any": true,
    "mfa_required_coverage_pct": 33,
    "mfa_required_users_count": 136,
    "session_lifetime_min_minutes": 15,
    "session_lifetime_max_minutes": 1440,
    "idle_timeout_min_minutes": 5,
    "idle_timeout_max_minutes": 120
  },

  "device_access": {
    "managed_device_required": true,
    "managed_device_required_coverage_pct": 75,
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

Each percentage below, and each of `mfa_required_all` and
`managed_device_required_for_admins`, has the count it is computed from beside
it, such as `mfa_enrolled_users_count` for `mfa_coverage` and `apps.sso_count`
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
| `total_count` | **Population.** Users other than deprovisioned ones. Every user percentage, including the MFA and policy coverage figures, is a share of this count. |
| `password_expired` | **Compliance and access issues.** Users with expired passwords may be locked out or using workarounds that bypass security controls. |
| `locked_out` | **Potential attack indicator.** Spikes in lockout rates may indicate brute force or credential stuffing attacks. |
| `inactive` | **Orphan account risk.** Inactive accounts (90+ days no login) are prime targets for attackers. They may belong to departed employees or unused service accounts. |
| `suspended` | **Disabled account coverage.** Suspended accounts should usually represent intentionally blocked access. Tracking the rate helps distinguish active workforce posture from dormant or intentionally disabled identities. |

### apps

Application lifecycle management health.

| Metric | Why It Matters |
|--------|----------------|
| `total_count` | **Population.** The apps that `sso_coverage` and the provisioning percentages are shares of. |
| `provisioning_enabled` | **Onboarding automation.** Manual provisioning delays access and increases admin burden. Automated provisioning ensures consistent access based on role. |
| `deprovisioning_enabled` | **Offboarding security.** Without automated deprovisioning, departing employees retain app access. This is a major source of data breaches. |

### privileged_access

Effective admin access across directly assigned and group-inherited role assignments.

| Metric | Why It Matters |
|--------|----------------|
| `privileged_users_count` | **Admin blast radius.** Counts active users with any effective Okta admin role. This is the main denominator for privileged identity risk. |
| `super_admin_count` | **Highest-risk accounts.** Super admins can fully control the tenant. Keep this count as low as possible. |
| `standing_privileged_users_count` | **Always-on privilege.** In Okta, standard admin roles are effectively standing access unless additional JIT tooling is used outside the collector. |
| `privileged_mfa_coverage_pct` | **Privileged account protection.** Measures how many active admins have any MFA factor enrolled. |
| `privileged_phishing_resistant_pct` | **Strong admin auth.** Tracks phishing-resistant MFA coverage for privileged users, the highest-value identity target set. |

### policy

Aggregated security policy settings across active sign-on and MFA-enrollment evaluation.

| Metric | Why It Matters |
|--------|----------------|
| `policy_count` | **Policy complexity.** Number of active sign-on policies. More policies mean more nuanced access control but also more complexity to audit. |
| `mfa_required_all` | **Universal MFA enforcement.** True only if all non-deprovisioned users are covered by an MFA requirement after policy evaluation. |
| `mfa_required_any` | **Any MFA enforcement.** True if at least one non-deprovisioned user is covered by an MFA requirement. |
| `mfa_required_coverage_pct` | **Actual MFA enforcement coverage.** Percentage of non-deprovisioned users covered by an MFA requirement after evaluating policy and rule scope, including group targeting. |
| `session_lifetime_min_minutes` | **Strictest session policy.** The shortest session lifetime across active sign-on rules. Indicates your most restrictive access control. |
| `session_lifetime_max_minutes` | **Most permissive session.** The longest session lifetime across active sign-on rules. Users under this policy have extended access windows. |
| `idle_timeout_min_minutes` | **Strictest idle policy.** The shortest idle timeout across active sign-on rules. Protects high-risk users from unattended sessions. |
| `idle_timeout_max_minutes` | **Most permissive idle timeout.** The longest idle timeout across active sign-on rules. Users under this policy stay logged in longer when inactive. |

### device_access

Device access enforcement posture based on sign-on policy rule conditions.

| Metric | Why It Matters |
|--------|----------------|
| `managed_device_required` | **Device trust enforcement.** True if any sign-on policy rule requires managed devices. Indicates that device-based access control is configured somewhere in the org. |
| `managed_device_required_coverage_pct` | **Device trust coverage.** Percentage of non-deprovisioned users covered by a managed device requirement after evaluating policy and rule scope, including group targeting. |
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

## Use Cases

- **Security Baseline Assessment**: Get a quick snapshot of your Okta security posture
- **Compliance Monitoring**: Track MFA adoption, device trust, and policy enforcement over time
- **Risk Identification**: Find inactive accounts, privileged exposure, unmanaged device access, and apps lacking deprovisioning
- **Benchmark Comparison**: Compare posture across multiple Okta organizations

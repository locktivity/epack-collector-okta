# Okta Collector Overview

The Okta collector gathers security posture metrics from your Okta organization. All metrics are percentages (0-100) or policy settings, designed to be actionable and comparable across organizations.

## Output Schema

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-02-25T19:46:39Z",
  "org_domain": "company.okta.com",

  "posture": {
    "mfa_coverage": 85,
    "mfa_phishing_resistant": 20,
    "sso_coverage": 90
  },

  "users": {
    "password_expired": 2,
    "locked_out": 0,
    "inactive": 15,
    "suspended": 3
  },

  "apps": {
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
  },

  "device_access": {
    "managed_device_required": true,
    "managed_device_required_coverage_pct": 75,
    "managed_device_required_for_admins": true,
    "device_assurance_policies_count": 3
  }
}
```

## Metrics Reference

### posture

High-level security scores for quick assessment.

| Metric | Why It Matters |
|--------|----------------|
| `mfa_coverage` | **Account takeover protection.** MFA significantly reduces credential-based attacks. Low coverage leaves accounts vulnerable to password spraying and phishing. |
| `mfa_phishing_resistant` | **Strong authentication.** WebAuthn/FIDO2 factors can't be phished, unlike SMS or TOTP. This is the gold standard for sensitive accounts. |
| `sso_coverage` | **Credential sprawl reduction.** Apps not using SSO require separate passwords, increasing password fatigue and reuse risk. |

### users

User account health indicators.

| Metric | Why It Matters |
|--------|----------------|
| `password_expired` | **Compliance and access issues.** Users with expired passwords may be locked out or using workarounds that bypass security controls. |
| `locked_out` | **Potential attack indicator.** Spikes in lockout rates may indicate brute force or credential stuffing attacks. |
| `inactive` | **Orphan account risk.** Inactive accounts (90+ days no login) are prime targets for attackers. They may belong to departed employees or unused service accounts. |
| `suspended` | **Disabled account coverage.** Suspended accounts should usually represent intentionally blocked access. Tracking the rate helps distinguish active workforce posture from dormant or intentionally disabled identities. |

### apps

Application lifecycle management health.

| Metric | Why It Matters |
|--------|----------------|
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

## Use Cases

- **Security Baseline Assessment**: Get a quick snapshot of your Okta security posture
- **Compliance Monitoring**: Track MFA adoption, device trust, and policy enforcement over time
- **Risk Identification**: Find inactive accounts, privileged exposure, unmanaged device access, and apps lacking deprovisioning
- **Benchmark Comparison**: Compare posture across multiple Okta organizations

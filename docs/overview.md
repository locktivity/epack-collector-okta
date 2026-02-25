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

### apps

Application lifecycle management health.

| Metric | Why It Matters |
|--------|----------------|
| `provisioning_enabled` | **Onboarding automation.** Manual provisioning delays access and increases admin burden. Automated provisioning ensures consistent access based on role. |
| `deprovisioning_enabled` | **Offboarding security.** Without automated deprovisioning, departing employees retain app access. This is a major source of data breaches. |

### policy

Aggregated security policy settings across all active sign-on policies.

| Metric | Why It Matters |
|--------|----------------|
| `policy_count` | **Policy complexity.** Number of active sign-on policies. More policies mean more nuanced access control but also more complexity to audit. |
| `mfa_required_all` | **Universal MFA enforcement.** True only if every policy requires MFA. If false, some user groups may bypass MFA. |
| `mfa_required_any` | **Partial MFA enforcement.** True if at least one policy requires MFA. Useful to detect if MFA is configured at all. |
| `session_lifetime_min_minutes` | **Strictest session policy.** The shortest session lifetime across all policies. Indicates your most restrictive access control. |
| `session_lifetime_max_minutes` | **Most permissive session.** The longest session lifetime. Users under this policy have extended access windows. |
| `idle_timeout_min_minutes` | **Strictest idle policy.** The shortest idle timeout. Protects high-risk users from unattended sessions. |
| `idle_timeout_max_minutes` | **Most permissive idle timeout.** The longest idle timeout. Users under this policy stay logged in longer when inactive. |

## Use Cases

- **Security Baseline Assessment**: Get a quick snapshot of your Okta security posture
- **Compliance Monitoring**: Track MFA adoption and policy enforcement over time
- **Risk Identification**: Find inactive accounts and apps lacking deprovisioning
- **Benchmark Comparison**: Compare posture across multiple Okta organizations

#!/usr/bin/env bash
#
# Fails the build if the collector source emits Okta data that must never leave
# the customer's org. The collector surfaces posture metadata and the login
# identifier only; user profile attributes beyond login, federation secrets, and
# hook auth material must never enter an artifact.
#
# Forbidden references:
#   - User profile attributes beyond login (FirstName, LastName, MobilePhone,
#     SecondaryEmail, RecoveryQuestion, UserType)
#   - IdP signing certs (.SAML.SigningCert)
#   - OIDC client secrets (.OIDC.ClientSecret)
#   - Hook authentication headers (.Channel.Headers)
#
# Escape hatch: prefix the call site with `// LINT-ALLOW: <reason>` if a future
# change has a legitimate reason to mention the symbol (e.g., a test asserting it
# was never emitted).

set -euo pipefail

cd "$(dirname "$0")/.."

violations=$(
  grep -rn -E '\.Profile\.(FirstName|LastName|MobilePhone|SecondaryEmail|RecoveryQuestion)|\.Profile\.UserType|\.SAML\.SigningCert|\.OIDC\.ClientSecret|\.Channel\.Headers' \
    internal/collector/ \
    --include='*.go' \
    | grep -v '_test.go' \
    | grep -v '// LINT-ALLOW:' \
    || true
)

if [ -n "$violations" ]; then
  echo "FORBIDDEN OKTA DATA EMISSION DETECTED"
  echo "These fields contain PII or secrets and must never appear in collector output:"
  echo "$violations"
  exit 1
fi

echo "forbidden-data check: OK"

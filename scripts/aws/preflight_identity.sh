#!/usr/bin/env bash
set -euo pipefail
ARN="$(aws sts get-caller-identity --query Arn --output text)"

if [[ "${ARN}" == *":root" && "${JUDIKT_ALLOW_ROOT_AWS:-false}" != "true" ]]; then
  cat >&2 <<'EOF'
Refusing to continue because the AWS CLI is using the account root identity.

Create an IAM user/role or use IAM Identity Center for deployment work.
For a one-off lab override, set:

  export JUDIKT_ALLOW_ROOT_AWS=true

EOF
  exit 3
fi

echo "${ARN}"

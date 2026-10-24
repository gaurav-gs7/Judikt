# CI/CD

Judikt uses GitHub Actions for validation and optional AWS deployment.

## CI Workflow

File:

```text
.github/workflows/ci.yml
```

Runs on push and pull request:

- installs the project with real MCP, observability, authentication, Redis, AWS, test, and quality profiles
- invokes one `scripts/run_release_tests.sh` gate for all Tier 1, Tier 2, and Tier 3 verification
- provisions isolated Redis and Vault containers and runs the complete suite without integration skips
- enforces 85% aggregate branch coverage and 100% coverage for secrets, audit export, Slack approval, and performance modules
- runs adversarial evals, failure drills, MCP-AttackBench adapter checks, and guarded-call performance thresholds
- runs pinned official Filesystem and Memory MCP interoperability checks
- packages the serverless Lambda artifact
- runs Terraform fmt and validate for both AWS modules
- builds the production MCP Docker image
- uploads sanitized coverage, attack-benchmark, performance, and interoperability evidence JSON

This workflow does not create AWS resources.

## AWS Deploy Workflow

File:

```text
.github/workflows/aws-deploy.yml
```

Runs only through manual `workflow_dispatch`.

Targets:

- `serverless`
- `ec2-real-mcp`

Required GitHub secrets:

- `AWS_DEPLOY_ROLE_ARN`
  - IAM role assumed through GitHub OIDC.
  - Do not use long-lived AWS access keys.
- `JUDIKT_APPROVAL_SECRET`
  - HMAC secret for signed approval tokens.
- `JUDIKT_AUDIT_HMAC_SECRET`
  - Independent HMAC secret for tamper-evident audit records.
- `JUDIKT_API_TOKEN`
  - Serverless API bearer token.
- `JUDIKT_HTTP_BEARER_TOKEN`
  - Real MCP Streamable HTTP bearer token.

The deploy scripts write these values into AWS Secrets Manager after Terraform creates the secret containers. The Terraform state owns secret ARNs and IAM wiring, but not the live secret strings.

Recommended GitHub environment:

```text
production
```

Add required reviewers to the environment so deploys need human approval.

## AWS OIDC Trust Policy Sketch

Use this shape for the deploy role trust policy, replacing owner/repo:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:<owner>/<repo>:*"
        }
      }
    }
  ]
}
```

## Design Rationale

> CI validates policy, failure modes, Terraform, Lambda packaging, and Docker builds. Deployment is manually gated through GitHub Actions OIDC and environment approvals, so there are no static AWS keys in the repo.

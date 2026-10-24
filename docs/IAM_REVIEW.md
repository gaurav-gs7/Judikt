# IAM Review

This document explains why each AWS permission exists. It keeps the project honest about least privilege.

## EC2 Real MCP Deployment

Role:

```text
judikt-tf-ec2-role-<region>
```

Permissions:

- `AmazonSSMManagedInstanceCore`
  - Required for SSM Session Manager access without SSH keys.
- `ecr:GetAuthorizationToken`
  - Required because Docker authenticates to ECR.
  - AWS requires this action to use resource `*`.
- `ecr:BatchCheckLayerAvailability`
- `ecr:BatchGetImage`
- `ecr:GetDownloadUrlForLayer`
  - Scoped to the Judikt ECR repository ARN.
  - Required to pull the container image.
- `secretsmanager:GetSecretValue`
  - Scoped to the HTTP bearer token and approval secret ARNs.
  - Required at boot to inject runtime secrets into the container.

Secret handling:

- Terraform creates the Secrets Manager secret resources and IAM bindings.
- Deploy scripts write secret values with `aws secretsmanager put-secret-value`.
- Secret values are intentionally not stored through `aws_secretsmanager_secret_version`, which avoids placing live secret strings in Terraform state.

Explicitly not granted:

- no `AdministratorAccess`
- no `iam:*`
- no write access to ECR
- no broad Secrets Manager access
- no SSH key access

## Serverless Deployment

Gateway Lambda role:

- `lambda:InvokeFunction`
  - Scoped to the mock tool Lambda.
- `dynamodb:GetItem`, `PutItem`, `Query`, `Scan`, `UpdateItem`
  - Scoped to state and audit tables.
- `events:PutEvents`
  - Scoped to the Judikt EventBridge bus.
- `cloudwatch:PutMetricData`
  - Restricted to namespace `Judikt/Serverless`.
- `secretsmanager:GetSecretValue`
  - Scoped to API token and approval secret.
- `AWSLambdaBasicExecutionRole`
  - Required for CloudWatch Logs.
- `AWSXRayDaemonWriteAccess`
  - Required for active Lambda tracing.

Tool Lambda role:

- DynamoDB access scoped to the state table.
- CloudWatch Logs.
- X-Ray write access.

EventBridge to SQS:

- SQS queue policy allows only the remediation findings EventBridge rule to send messages.

Secret handling:

- Terraform creates API-token and approval-secret containers.
- The deploy script writes values after the secret resources exist.
- Lambda receives only secret ARNs in environment variables.

## Review Checklist

- Every wildcard action must have a written justification.
- Every secret read must be scoped to a specific secret ARN.
- Destructive tool capability must require signed approval.
- No root AWS identity should be used for deployment.
- GitHub Actions must use OIDC and a deploy role, not long-lived AWS access keys.

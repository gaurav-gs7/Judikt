# Judikt Terraform Deployment

This Terraform module is the production-facing real MCP deployment path for Judikt. It provisions:

- Amazon ECR repository with scan-on-push and AES256 encryption
- ECR lifecycle policy that keeps the most recent five images
- EC2 instance profile and IAM role
- SSM Session Manager permissions
- Security group for the dashboard port
- One encrypted-root-volume EC2 instance running the Judikt Docker image
- Official MCP Streamable HTTP endpoint at `/mcp`
- Health and Prometheus-style metrics endpoints at `/healthz` and `/metrics`
- AWS Secrets Manager storage for bearer-token, approval-token, and independent audit-signing secrets

The module uses default names that avoid colliding with the CloudFormation demo path.

## Fast Path

From the repository root:

```bash
export AWS_REGION=us-east-1
export JUDIKT_ALLOWED_CIDR="$(curl -s https://checkip.amazonaws.com)/32"
export JUDIKT_MODE=real-mcp
export JUDIKT_HTTP_BEARER_TOKEN="$(openssl rand -hex 24)"
export JUDIKT_APPROVAL_SECRET="$(openssl rand -hex 32)"
export JUDIKT_AUDIT_HMAC_SECRET="$(openssl rand -hex 32)"
./scripts/aws/deploy_terraform.sh
```

Destroy resources after the demo:

```bash
./scripts/aws/destroy_terraform.sh
```

For ARM/free-tier experiments:

```bash
export JUDIKT_INSTANCE_TYPE=t4g.micro
export JUDIKT_DOCKER_PLATFORM=linux/arm64
export JUDIKT_AMI_SSM_PARAMETER=/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64
./scripts/aws/deploy_terraform.sh
```

## Manual Path

```bash
cd infra/aws/terraform
terraform init
terraform apply -target=aws_ecr_repository.app
```

Then build and push the image from the repository root:

```bash
export JUDIKT_ECR_REPOSITORY=judikt-terraform
export JUDIKT_IMAGE_TAG=latest
IMAGE_URI=$(./scripts/aws/build_push_ecr.sh)
echo "$IMAGE_URI"
```

Finish the infrastructure apply:

```bash
cd infra/aws/terraform
terraform apply \
  -var="repository_name=judikt-terraform" \
  -var="image_tag=latest" \
  -var="allowed_cidr=<your-public-ip>/32"
```

Terraform outputs the dashboard URL and SSM command.

In `real-mcp` mode, point MCP clients to:

```text
http://<public-dns>:8080/mcp
```

Use the bearer token through an `Authorization: Bearer ...` header when your MCP client supports custom headers. If not, restrict the security group to your own IP and treat the network boundary as the demo control.

Terraform creates the secret containers and IAM permissions. The deploy script writes secret values with AWS CLI so live secret strings are not stored through Terraform-managed secret-version resources.

## Infrastructure Choice

Terraform is the primary deployment path because it provides stateful, repeatable provisioning and cleanup across the EC2, ECR, IAM, networking, secrets, and observability resources. CloudFormation remains available as the AWS-native baseline.

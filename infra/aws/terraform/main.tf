provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ssm_parameter" "latest_ami" {
  name = var.ami_ssm_parameter
}

locals {
  common_tags = {
    Project     = "Judikt"
    ManagedBy   = "Terraform"
    Environment = "demo"
  }

  image_uri = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.repository_name}:${var.image_tag}"
}

resource "aws_ecr_repository" "app" {
  name                 = var.repository_name
  image_tag_mutability = "MUTABLE"
  force_delete         = var.ecr_force_delete

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the most recent five images for free-tier hygiene"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_secretsmanager_secret" "http_bearer_token" {
  name                    = "${var.app_name}/http-bearer-token"
  description             = "Bearer token for remote MCP Streamable HTTP callers."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "approval_secret" {
  name                    = "${var.app_name}/approval-secret"
  description             = "HMAC secret for Judikt signed approval tokens."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "audit_hmac_secret" {
  name                    = "${var.app_name}/audit-hmac-secret"
  description             = "Independent HMAC secret for Judikt audit evidence."
  recovery_window_in_days = 0
}

resource "aws_iam_role" "instance" {
  name = "${var.app_name}-ec2-role-${var.aws_region}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "ecr_pull" {
  name = "runtime-access"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer"
        ]
        Resource = aws_ecr_repository.app.arn
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.http_bearer_token.arn,
          aws_secretsmanager_secret.approval_secret.arn,
          aws_secretsmanager_secret.audit_hmac_secret.arn
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.app_name}-instance-profile-${var.aws_region}"
  role = aws_iam_role.instance.name
}

resource "aws_security_group" "app" {
  name        = "${var.app_name}-sg"
  description = "Allow HTTP access to Judikt"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Judikt dashboard"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  egress {
    description = "Allow outbound package, ECR, and telemetry traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  ami                         = data.aws_ssm_parameter.latest_ami.value
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnets.default.ids[0]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  vpc_security_group_ids      = [aws_security_group.app.id]
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size           = var.root_volume_size_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  user_data = <<-USERDATA
#!/bin/bash
set -euo pipefail

dnf update -y
dnf install -y docker awscli
systemctl enable --now docker

install -d -o 10001 -g 10001 /opt/judikt/data

aws ecr get-login-password --region ${var.aws_region} \
  | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com

docker pull ${local.image_uri}
docker rm -f judikt || true

HTTP_BEARER_TOKEN="$(aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${aws_secretsmanager_secret.http_bearer_token.arn} --query SecretString --output text)"
APPROVAL_SECRET="$(aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${aws_secretsmanager_secret.approval_secret.arn} --query SecretString --output text)"
AUDIT_HMAC_SECRET="$(aws secretsmanager get-secret-value --region ${var.aws_region} --secret-id ${aws_secretsmanager_secret.audit_hmac_secret.arn} --query SecretString --output text)"

docker run -d \
  --name judikt \
  --restart unless-stopped \
  -p ${var.app_port}:8080 \
  -v /opt/judikt/data:/app/data \
  -e JUDIKT_MODE=${var.container_mode} \
  -e JUDIKT_TELEMETRY=${var.telemetry_mode} \
  -e JUDIKT_HTTP_BEARER_TOKEN="$HTTP_BEARER_TOKEN" \
  -e JUDIKT_APPROVAL_SECRET="$APPROVAL_SECRET" \
  -e JUDIKT_AUDIT_HMAC_SECRET="$AUDIT_HMAC_SECRET" \
  -e JUDIKT_AUDIT_SIGNATURE_REQUIRED=true \
  -e JUDIKT_AUDIT_VERIFY_ON_STARTUP=true \
  -e JUDIKT_SINGLE_INSTANCE=true \
  ${local.image_uri}
  USERDATA

  tags = {
    Name = var.app_name
  }

  depends_on = [
    aws_ecr_lifecycle_policy.app,
    aws_secretsmanager_secret.http_bearer_token,
    aws_secretsmanager_secret.approval_secret,
    aws_secretsmanager_secret.audit_hmac_secret,
    aws_iam_role_policy.ecr_pull,
    aws_iam_role_policy_attachment.ssm
  ]
}

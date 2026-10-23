variable "aws_region" {
  description = "AWS region for all Judikt resources."
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "Name prefix for EC2, IAM, and security group resources."
  type        = string
  default     = "judikt-tf"
}

variable "repository_name" {
  description = "ECR repository name for the Judikt container image."
  type        = string
  default     = "judikt"
}

variable "image_tag" {
  description = "Container image tag to run on EC2."
  type        = string
  default     = "latest"
}

variable "instance_type" {
  description = "Free-tier friendly EC2 instance type. Keep the AMI architecture aligned with the instance family."
  type        = string
  default     = "t3.micro"

  validation {
    condition     = contains(["t2.micro", "t3.micro", "t4g.micro"], var.instance_type)
    error_message = "instance_type must be one of: t2.micro, t3.micro, t4g.micro."
  }
}

variable "ami_ssm_parameter" {
  description = "SSM parameter for the Amazon Linux 2023 AMI. Use an arm64 parameter when instance_type is t4g.micro."
  type        = string
  default     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

variable "app_port" {
  description = "Host port exposed by the Judikt dashboard."
  type        = number
  default     = 8080
}

variable "allowed_cidr" {
  description = "CIDR allowed to reach Judikt. Defaults to loopback-only; set your public IP /32 for remote demos."
  type        = string
  default     = "127.0.0.1/32"

  validation {
    condition     = can(cidrhost(var.allowed_cidr, 0))
    error_message = "allowed_cidr must be a valid CIDR block, for example 203.0.113.10/32."
  }
}

variable "root_volume_size_gb" {
  description = "Encrypted root EBS volume size."
  type        = number
  default     = 8
}

variable "telemetry_mode" {
  description = "Judikt telemetry mode inside the container."
  type        = string
  default     = "disabled"

  validation {
    condition     = contains(["disabled", "console", "otlp"], var.telemetry_mode)
    error_message = "telemetry_mode must be disabled, console, or otlp."
  }
}

variable "container_mode" {
  description = "Container entrypoint mode. Use real-mcp for the production MCP server or dashboard for the local HTTP demo."
  type        = string
  default     = "real-mcp"

  validation {
    condition     = contains(["real-mcp", "dashboard"], var.container_mode)
    error_message = "container_mode must be real-mcp or dashboard."
  }
}

variable "http_bearer_token" {
  description = "Optional bearer token for the real MCP HTTP server. Leave empty to rely on network boundaries such as a restricted security group."
  type        = string
  default     = ""
  sensitive   = true
}

variable "approval_secret" {
  description = "HMAC secret for signed Judikt approval tokens."
  type        = string
  default     = ""
  sensitive   = true
}

variable "ecr_force_delete" {
  description = "Allow terraform destroy to delete the ECR repository even when it contains demo images."
  type        = bool
  default     = true
}

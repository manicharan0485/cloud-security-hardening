# ─────────────────────────────────────────────────────────────────────────────
# Environment: aws/environments/prod
# Calls all security hardening modules for a production AWS account.
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state — replace with your S3 bucket + DynamoDB table
  backend "s3" {
    bucket         = "YOUR-TERRAFORM-STATE-BUCKET"
    key            = "cloud-security/prod/terraform.tfstate"
    region         = "eu-central-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  common_tags = {
    Environment = "prod"
    ManagedBy   = "terraform"
    Project     = "cloud-security-hardening"
    Owner       = "cloud-security-team"
  }
}

# ─── Security Hub ─────────────────────────────────────────────────────────────

module "security_hub" {
  source      = "../../modules/security-hub"
  prefix      = "${var.prefix}-prod"
  region      = var.region
  alert_email = var.alert_email
  enable_nist = false
  tags        = local.common_tags
}

# ─── GuardDuty ────────────────────────────────────────────────────────────────

module "guardduty" {
  source           = "../../modules/guardduty"
  prefix           = "${var.prefix}-prod"
  account_id       = local.account_id
  region           = var.region
  sns_topic_arns   = [module.security_hub.sns_topic_arn]
  finding_frequency = "FIFTEEN_MINUTES"
  tags             = local.common_tags
}

# ─── IAM Hardening + CloudTrail ───────────────────────────────────────────────

module "iam_hardening" {
  source                   = "../../modules/iam-hardening"
  prefix                   = "${var.prefix}-prod"
  account_id               = local.account_id
  region                   = var.region
  min_password_length      = 14
  max_password_age         = 90
  password_reuse_prevention = 24
  sns_topic_arns           = [module.security_hub.sns_topic_arn]
  tags                     = local.common_tags
}

# ─── S3 Security ──────────────────────────────────────────────────────────────

module "s3_security" {
  source               = "../../modules/s3-security"
  prefix               = "${var.prefix}-prod"
  bucket_names         = var.s3_buckets_to_harden
  use_kms              = true
  kms_key_arn          = var.kms_key_arn
  enable_access_logging = true
  logging_bucket       = module.guardduty.findings_bucket
  tags                 = local.common_tags
}

# ─── Outputs ─────────────────────────────────────────────────────────────────

output "security_hub_arn" {
  value = module.security_hub.sns_topic_arn
}

output "guardduty_detector_id" {
  value = module.guardduty.detector_id
}

output "cloudtrail_arn" {
  value = module.iam_hardening.cloudtrail_arn
}

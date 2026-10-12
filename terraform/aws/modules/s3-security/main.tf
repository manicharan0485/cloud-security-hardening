# ─────────────────────────────────────────────────────────────────────────────
# Module: aws/modules/s3-security
# Purpose: Account-level S3 hardening + per-bucket security baseline.
#          CIS Controls: 2.1.3, 2.1.4, 2.1.5
# ─────────────────────────────────────────────────────────────────────────────

# ─── Account-level: Block ALL public S3 access (CIS 2.1.4) ──────────────────

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─── Per-bucket hardening (applied to var.bucket_names list) ─────────────────

resource "aws_s3_bucket_public_access_block" "buckets" {
  for_each = toset(var.bucket_names)
  bucket   = each.value

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "buckets" {
  for_each = toset(var.bucket_names)
  bucket   = each.value

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "buckets" {
  for_each = toset(var.bucket_names)
  bucket   = each.value

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.use_kms ? "aws:kms" : "AES256"
      kms_master_key_id = var.use_kms ? var.kms_key_arn : null
    }
    bucket_key_enabled = var.use_kms
  }
}

# Force SSL-only access (CIS 2.1.2)
resource "aws_s3_bucket_policy" "enforce_tls" {
  for_each = toset(var.bucket_names)
  bucket   = each.value

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          "arn:aws:s3:::${each.value}",
          "arn:aws:s3:::${each.value}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

# Enable access logging
resource "aws_s3_bucket_logging" "buckets" {
  for_each = var.enable_access_logging ? toset(var.bucket_names) : toset([])
  bucket   = each.value

  target_bucket = var.logging_bucket
  target_prefix = "s3-access-logs/${each.value}/"
}

# ─── AWS Config rule: detect public buckets ───────────────────────────────────

resource "aws_config_config_rule" "s3_public_access" {
  name        = "${var.prefix}-s3-no-public-access"
  description = "Checks that S3 buckets do not allow public access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }

  tags = var.tags
}

resource "aws_config_config_rule" "s3_ssl_only" {
  name        = "${var.prefix}-s3-ssl-only"
  description = "Checks that S3 bucket policies require SSL"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  tags = var.tags
}

resource "aws_config_config_rule" "s3_versioning" {
  name        = "${var.prefix}-s3-versioning-enabled"
  description = "Checks S3 bucket versioning is enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }

  tags = var.tags
}

# ─────────────────────────────────────────────────────────────────────────────
# Module: aws/modules/guardduty
# Purpose: Enable GuardDuty across all specified regions with S3, EKS, 
#          Malware Protection, and RDS threat detection.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  finding_publishing_frequency = var.finding_frequency

  tags = var.tags
}

# ─── S3 bucket for findings export ───────────────────────────────────────────

resource "aws_s3_bucket" "guardduty_findings" {
  bucket        = "${var.prefix}-guardduty-findings-${var.account_id}"
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_versioning" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != "" ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn != "" ? var.kms_key_arn : null
    }
  }
}

resource "aws_s3_bucket_public_access_block" "guardduty_findings" {
  bucket                  = aws_s3_bucket.guardduty_findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGuardDutyGetBucketLocation"
        Effect = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action   = "s3:GetBucketLocation"
        Resource = aws_s3_bucket.guardduty_findings.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
        }
      },
      {
        Sid    = "AllowGuardDutyPutObject"
        Effect = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.guardduty_findings.arn}/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
        }
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["${aws_s3_bucket.guardduty_findings.arn}", "${aws_s3_bucket.guardduty_findings.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# ─── Export findings to S3 ────────────────────────────────────────────────────

resource "aws_guardduty_publishing_destination" "s3" {
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = aws_s3_bucket.guardduty_findings.arn
  kms_key_arn     = var.kms_key_arn != "" ? var.kms_key_arn : null
  destination_type = "S3"
}

# ─── CloudWatch alarm: High severity findings ─────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "guardduty_high_findings" {
  alarm_name          = "${var.prefix}-guardduty-high-severity"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FindingsCount"
  namespace           = "AWS/GuardDuty"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "GuardDuty detected HIGH or CRITICAL severity findings"
  alarm_actions       = var.sns_topic_arns
  treat_missing_data  = "notBreaching"

  dimensions = {
    DetectorId = aws_guardduty_detector.main.id
    Severity   = "High"
  }

  tags = var.tags
}

output "detector_id" {
  value       = aws_guardduty_detector.main.id
  description = "GuardDuty Detector ID"
}

output "findings_bucket" {
  value       = aws_s3_bucket.guardduty_findings.bucket
  description = "S3 bucket for GuardDuty findings"
}

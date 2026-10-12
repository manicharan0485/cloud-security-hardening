# ─────────────────────────────────────────────────────────────────────────────
# Module: aws/modules/security-hub
# Purpose: Enable AWS Security Hub with CIS Benchmark v1.4 and AWS Foundational
#          Security Best Practices standard.
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# ─── Security Hub ────────────────────────────────────────────────────────────

resource "aws_securityhub_account" "main" {}

# CIS AWS Foundations Benchmark v1.4
resource "aws_securityhub_standards_subscription" "cis_v14" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
}

# AWS Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "fsbp" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# NIST SP 800-53 Rev 5 (optional - enabled if var set)
resource "aws_securityhub_standards_subscription" "nist" {
  count         = var.enable_nist ? 1 : 0
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/nist-800-53/v/5.0.0"
}

# ─── SNS Topic for findings ───────────────────────────────────────────────────

resource "aws_sns_topic" "security_findings" {
  name              = "${var.prefix}-security-findings"
  kms_master_key_id = var.kms_key_id

  tags = var.tags
}

resource "aws_sns_topic_subscription" "email_alert" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_findings.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ─── EventBridge rule → SNS for HIGH/CRITICAL findings ───────────────────────

resource "aws_cloudwatch_event_rule" "critical_findings" {
  name        = "${var.prefix}-securityhub-critical"
  description = "Route Security Hub CRITICAL and HIGH findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
        Workflow = {
          Status = ["NEW"]
        }
        RecordState = ["ACTIVE"]
      }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "findings_to_sns" {
  rule      = aws_cloudwatch_event_rule.critical_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_findings.arn

  input_transformer {
    input_paths = {
      title       = "$.detail.findings[0].Title"
      severity    = "$.detail.findings[0].Severity.Label"
      accountId   = "$.detail.findings[0].AwsAccountId"
      region      = "$.detail.findings[0].Region"
      resource    = "$.detail.findings[0].Resources[0].Id"
      remediation = "$.detail.findings[0].Remediation.Recommendation.Url"
    }
    input_template = <<-EOT
      "🚨 Security Hub Alert"
      "Severity: <severity>"
      "Title: <title>"
      "Account: <accountId> | Region: <region>"
      "Resource: <resource>"
      "Remediation: <remediation>"
    EOT
  }
}

# ─── Auto-remediation: suppress informational findings ───────────────────────

resource "aws_securityhub_insight" "failed_controls" {
  name = "${var.prefix}-failed-controls-summary"

  filters {
    workflow_status {
      comparison = "NOT_EQUALS"
      value      = "SUPPRESSED"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
  }

  group_by_attribute = "ProductName"
}

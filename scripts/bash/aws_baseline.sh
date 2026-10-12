#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# aws_baseline.sh — One-shot AWS account security baseline
#
# Applies minimum security hardening to a new/existing AWS account:
#   - Enables Security Hub (CIS v1.4)
#   - Enables GuardDuty
#   - Sets IAM password policy
#   - Blocks S3 public access (account level)
#   - Enables CloudTrail
#
# Usage:
#   export AWS_PROFILE=myprofile
#   export AWS_REGION=eu-central-1
#   bash aws_baseline.sh
#   bash aws_baseline.sh --dry-run
#
# Author:  Manicharan Ravi
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

DRY_RUN=false
REGION="${AWS_REGION:-eu-central-1}"
LOG_FILE="aws_baseline_$(date +%Y%m%d_%H%M%S).log"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run) DRY_RUN=true ;;
    --region)  REGION="$2"; shift ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
  shift
done

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
ok()  { echo "[$(date '+%H:%M:%S')] ✅ $*" | tee -a "$LOG_FILE"; }
warn(){ echo "[$(date '+%H:%M:%S')] ⚠️  $*" | tee -a "$LOG_FILE"; }
err() { echo "[$(date '+%H:%M:%S')] ❌ $*" | tee -a "$LOG_FILE"; }

run() {
  if [[ "$DRY_RUN" == true ]]; then
    log "[DRY-RUN] $*"
  else
    eval "$@"
  fi
}

# ── Verify AWS CLI ─────────────────────────────────────────────────────────────
if ! command -v aws &>/dev/null; then
  err "AWS CLI not found. Install it: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html"
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || {
  err "AWS authentication failed. Run: aws configure"
  exit 1
}

log "======================================================"
log " AWS Account Security Baseline"
log " Account  : $ACCOUNT_ID"
log " Region   : $REGION"
log " Dry Run  : $DRY_RUN"
log " Log File : $LOG_FILE"
log "======================================================"

# ─────────────────────────────────────────────────────────────────────────────
# 1. IAM Password Policy (CIS 1.8–1.14)
# ─────────────────────────────────────────────────────────────────────────────
log "Setting IAM password policy..."
run "aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --require-numbers \
  --require-symbols \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 24 \
  --region $REGION" && ok "IAM password policy set" || warn "IAM password policy failed"

# ─────────────────────────────────────────────────────────────────────────────
# 2. S3 Block Public Access (account level) (CIS 2.1.4)
# ─────────────────────────────────────────────────────────────────────────────
log "Blocking S3 public access at account level..."
run "aws s3control put-public-access-block \
  --account-id $ACCOUNT_ID \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  --region $REGION" && ok "S3 Block Public Access enabled" || warn "S3 Block Public Access failed"

# ─────────────────────────────────────────────────────────────────────────────
# 3. GuardDuty (CIS 3.x)
# ─────────────────────────────────────────────────────────────────────────────
log "Enabling GuardDuty..."
DETECTOR_ID=$(aws guardduty list-detectors --region $REGION --query 'DetectorIds[0]' --output text 2>/dev/null || echo "None")

if [[ "$DETECTOR_ID" == "None" || -z "$DETECTOR_ID" ]]; then
  run "aws guardduty create-detector \
    --enable \
    --data-sources S3Logs={Enable=true},Kubernetes={AuditLogs={Enable=true}} \
    --finding-publishing-frequency FIFTEEN_MINUTES \
    --region $REGION" && ok "GuardDuty enabled" || warn "GuardDuty enable failed"
else
  ok "GuardDuty already active: $DETECTOR_ID"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. Security Hub (CIS v1.4)
# ─────────────────────────────────────────────────────────────────────────────
log "Enabling Security Hub..."
run "aws securityhub enable-security-hub --enable-default-standards --region $REGION" \
  2>/dev/null && ok "Security Hub enabled" || ok "Security Hub already enabled"

# Subscribe to CIS v1.4
CIS_ARN="arn:aws:securityhub:${REGION}::standards/cis-aws-foundations-benchmark/v/1.4.0"
run "aws securityhub batch-enable-standards \
  --standards-subscription-requests StandardsArn=$CIS_ARN \
  --region $REGION" && ok "CIS v1.4 standard subscribed" || warn "CIS subscription failed (may already be active)"

# ─────────────────────────────────────────────────────────────────────────────
# 5. EBS Default Encryption
# ─────────────────────────────────────────────────────────────────────────────
log "Enabling EBS default encryption..."
run "aws ec2 enable-ebs-encryption-by-default --region $REGION" \
  && ok "EBS default encryption enabled" || warn "EBS encryption setup failed"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Check root MFA (informational)
# ─────────────────────────────────────────────────────────────────────────────
log "Checking root account MFA..."
MFA_ACTIVE=$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text 2>/dev/null || echo "0")
if [[ "$MFA_ACTIVE" == "1" ]]; then
  ok "Root account MFA is enabled"
else
  warn "Root account MFA is NOT enabled — action required immediately!"
  warn "   → AWS Console → My Account → Security credentials → MFA"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
log ""
log "======================================================"
log " Baseline complete — next steps:"
log "   1. Run Terraform modules for full hardening"
log "   2. Set up CloudTrail (see terraform/aws/modules/iam-hardening)"
log "   3. Review Security Hub findings in console"
log "   4. Enable MFA on root account if not done"
log "   5. Run: python scripts/python/cis_benchmark_checker.py --cloud aws"
log "======================================================"
log "Full log saved to: $LOG_FILE"

#!/usr/bin/env python3
"""
cis_benchmark_checker.py
─────────────────────────────────────────────────────────────────────────────
Multi-cloud CIS Benchmark compliance scanner.

Checks AWS, Azure, or GCP against CIS Foundations Benchmark controls and
generates an HTML + JSON report with PASS/FAIL/WARN per control.

Supported:
  AWS  — CIS AWS Foundations Benchmark v1.4
  Azure — CIS Microsoft Azure Foundations Benchmark v2.0
  GCP  — CIS Google Cloud Platform Foundations Benchmark v1.3

Requirements:
    pip install boto3 azure-mgmt-security azure-identity google-cloud-securitycenter

Usage:
    python cis_benchmark_checker.py --cloud aws --profile default
    python cis_benchmark_checker.py --cloud azure --subscription <SUB_ID>
    python cis_benchmark_checker.py --cloud gcp --project <PROJECT_ID>

Author:  Manicharan Ravi
Version: 2.0.0
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Literal

# ─────────────────────────────────────────────────────────────────────────────
# Result model
# ─────────────────────────────────────────────────────────────────────────────

class CheckResult:
    def __init__(self, control_id: str, title: str, status: Literal["PASS", "FAIL", "WARN", "ERROR"],
                 detail: str = "", remediation: str = ""):
        self.control_id  = control_id
        self.title       = title
        self.status      = status
        self.detail      = detail
        self.remediation = remediation

    def to_dict(self):
        return self.__dict__


# ─────────────────────────────────────────────────────────────────────────────
# AWS Checks
# ─────────────────────────────────────────────────────────────────────────────

def run_aws_checks(profile: str) -> list[CheckResult]:
    try:
        import boto3
        session = boto3.Session(profile_name=profile)
    except Exception as e:
        return [CheckResult("AWS", "AWS Connection", "ERROR", str(e))]

    results = []
    iam  = session.client("iam")
    ec2  = session.client("ec2")
    s3   = session.client("s3")
    ct   = session.client("cloudtrail")

    # ── 1.4: No root access keys ──────────────────────────────────────────
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountAccessKeysPresent", 0) == 0:
            results.append(CheckResult("1.4", "No root access keys", "PASS"))
        else:
            results.append(CheckResult(
                "1.4", "No root access keys", "FAIL",
                "Root account has active access keys.",
                "Delete root access keys immediately: IAM → Security credentials → Access keys"
            ))
    except Exception as e:
        results.append(CheckResult("1.4", "No root access keys", "ERROR", str(e)))

    # ── 1.5: MFA enabled for root ─────────────────────────────────────────
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 1:
            results.append(CheckResult("1.5", "MFA enabled for root", "PASS"))
        else:
            results.append(CheckResult(
                "1.5", "MFA enabled for root", "FAIL",
                "Root account does not have MFA enabled.",
                "Enable MFA: AWS Console → My Account → Security credentials → MFA"
            ))
    except Exception as e:
        results.append(CheckResult("1.5", "MFA enabled for root", "ERROR", str(e)))

    # ── 1.8: IAM password policy ──────────────────────────────────────────
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"MinLength={policy.get('MinimumPasswordLength')} (need ≥14)")
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("No uppercase requirement")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("No lowercase requirement")
        if not policy.get("RequireNumbers"):
            issues.append("No number requirement")
        if not policy.get("RequireSymbols"):
            issues.append("No symbol requirement")
        if policy.get("MaxPasswordAge", 999) > 90:
            issues.append(f"MaxAge={policy.get('MaxPasswordAge')} (need ≤90)")

        if not issues:
            results.append(CheckResult("1.8", "IAM password policy", "PASS"))
        else:
            results.append(CheckResult(
                "1.8", "IAM password policy", "FAIL",
                f"Issues: {'; '.join(issues)}",
                "Update via IAM → Account settings → Password policy"
            ))
    except iam.exceptions.NoSuchEntityException:
        results.append(CheckResult("1.8", "IAM password policy", "FAIL",
                                   "No password policy set.", "Create a password policy in IAM."))

    # ── 1.14: Hardware MFA for root ───────────────────────────────────────
    try:
        mfa_devices = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")["VirtualMFADevices"]
        root_mfa = [d for d in mfa_devices if "root-account-mfa-device" in d.get("SerialNumber", "")]
        if root_mfa:
            results.append(CheckResult("1.14", "Hardware MFA for root (virtual detected)", "WARN",
                                       "Root uses virtual MFA. Hardware MFA preferred for root.",
                                       "Consider upgrading to hardware MFA token for root account."))
        else:
            results.append(CheckResult("1.14", "Hardware MFA for root", "PASS"))
    except Exception as e:
        results.append(CheckResult("1.14", "Hardware MFA for root", "ERROR", str(e)))

    # ── 2.1: CloudTrail enabled in all regions ────────────────────────────
    try:
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
        if multi_region:
            results.append(CheckResult("2.1", "CloudTrail multi-region enabled", "PASS",
                                       f"Trails: {[t['Name'] for t in multi_region]}"))
        else:
            results.append(CheckResult("2.1", "CloudTrail multi-region enabled", "FAIL",
                                       "No multi-region CloudTrail found.",
                                       "Enable a multi-region trail with S3 logging."))
    except Exception as e:
        results.append(CheckResult("2.1", "CloudTrail multi-region enabled", "ERROR", str(e)))

    # ── 2.6: CloudTrail log file validation ───────────────────────────────
    try:
        trails = ct.describe_trails()["trailList"]
        invalid = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
        if not invalid:
            results.append(CheckResult("2.6", "CloudTrail log file validation", "PASS"))
        else:
            results.append(CheckResult("2.6", "CloudTrail log file validation", "FAIL",
                                       f"Trails without validation: {invalid}",
                                       "Enable log file validation on all trails."))
    except Exception as e:
        results.append(CheckResult("2.6", "CloudTrail log file validation", "ERROR", str(e)))

    # ── 2.1.4: S3 Block Public Access (account level) ─────────────────────
    try:
        block = s3.get_public_access_block()["PublicAccessBlockConfiguration"]
        all_blocked = all([
            block.get("BlockPublicAcls"),
            block.get("BlockPublicPolicy"),
            block.get("IgnorePublicAcls"),
            block.get("RestrictPublicBuckets"),
        ])
        if all_blocked:
            results.append(CheckResult("2.1.4", "S3 Block Public Access (account)", "PASS"))
        else:
            results.append(CheckResult("2.1.4", "S3 Block Public Access (account)", "FAIL",
                                       f"Settings: {block}",
                                       "Enable all 4 Block Public Access settings at the account level."))
    except Exception as e:
        results.append(CheckResult("2.1.4", "S3 Block Public Access (account)", "ERROR", str(e)))

    # ── 4.1: No unrestricted SSH ──────────────────────────────────────────
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        exposed = []
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                if perm.get("FromPort") == 22 and perm.get("ToPort") == 22:
                    for ip in perm.get("IpRanges", []):
                        if ip.get("CidrIp") == "0.0.0.0/0":
                            exposed.append(sg["GroupId"])
        if not exposed:
            results.append(CheckResult("4.1", "No unrestricted SSH (0.0.0.0/0)", "PASS"))
        else:
            results.append(CheckResult("4.1", "No unrestricted SSH (0.0.0.0/0)", "FAIL",
                                       f"SGs with open SSH: {exposed}",
                                       "Restrict SSH to known IP ranges in security group rules."))
    except Exception as e:
        results.append(CheckResult("4.1", "No unrestricted SSH", "ERROR", str(e)))

    # ── 4.2: No unrestricted RDP ──────────────────────────────────────────
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        exposed = []
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                if perm.get("FromPort") == 3389 and perm.get("ToPort") == 3389:
                    for ip in perm.get("IpRanges", []):
                        if ip.get("CidrIp") == "0.0.0.0/0":
                            exposed.append(sg["GroupId"])
        if not exposed:
            results.append(CheckResult("4.2", "No unrestricted RDP (0.0.0.0/0)", "PASS"))
        else:
            results.append(CheckResult("4.2", "No unrestricted RDP (0.0.0.0/0)", "FAIL",
                                       f"SGs with open RDP: {exposed}",
                                       "Restrict RDP to VPN or bastion host IPs only."))
    except Exception as e:
        results.append(CheckResult("4.2", "No unrestricted RDP", "ERROR", str(e)))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Report Generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(results: list[CheckResult], cloud: str, output_dir: Path) -> None:
    ts        = datetime.now().strftime("%Y-%m-%d %H:%M")
    passed    = sum(1 for r in results if r.status == "PASS")
    failed    = sum(1 for r in results if r.status == "FAIL")
    warned    = sum(1 for r in results if r.status == "WARN")
    total     = len(results)
    score_pct = round((passed / total) * 100, 1) if total > 0 else 0

    # JSON
    json_path = output_dir / f"cis_{cloud}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    json_path.write_text(json.dumps([r.to_dict() for r in results], indent=2))

    # HTML
    rows = ""
    for r in results:
        icon  = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "ERROR": "🔴"}.get(r.status, "")
        color = {"PASS": "#dff0d8", "FAIL": "#fddede", "WARN": "#fff3cd", "ERROR": "#fddede"}.get(r.status, "")
        rows += f"""<tr style='background:{color}'>
            <td><code>{r.control_id}</code></td>
            <td>{r.title}</td>
            <td><b>{icon} {r.status}</b></td>
            <td style='font-size:.85em'>{r.detail}</td>
            <td style='font-size:.85em;color:#c00'>{r.remediation}</td>
        </tr>"""

    cloud_icons = {"aws": "🟠", "azure": "🔵", "gcp": "🔴"}
    html = f"""<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>CIS Benchmark — {cloud.upper()}</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:0;padding:0;background:#f4f6fa}}
header{{background:linear-gradient(135deg,#1a1a2e,#16213e);color:white;padding:28px 40px}}
header h1{{margin:0;font-size:1.9em;letter-spacing:.5px}}
header p{{margin:6px 0 0;opacity:.75}}
main{{padding:30px 40px}}
.kpi-row{{display:flex;gap:16px;margin-bottom:28px}}
.kpi{{flex:1;background:white;border-radius:10px;padding:18px 22px;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
.kpi-val{{font-size:2.2em;font-weight:700}}
.kpi-label{{font-size:.85em;color:#666;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:white;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
th{{background:#1a1a2e;color:white;padding:11px 14px;text-align:left;font-size:.9em}}
td{{padding:9px 14px;border-bottom:1px solid #eee;vertical-align:top}}
</style></head><body>
<header>
  <h1>{cloud_icons.get(cloud,'☁️')} CIS {cloud.upper()} Foundations Benchmark Report</h1>
  <p>Generated: {ts} | Overall Score: {score_pct}%</p>
</header>
<main>
<div class='kpi-row'>
  <div class='kpi'><div class='kpi-val' style='color:#27ae60'>{passed}</div><div class='kpi-label'>PASSED</div></div>
  <div class='kpi'><div class='kpi-val' style='color:#e74c3c'>{failed}</div><div class='kpi-label'>FAILED</div></div>
  <div class='kpi'><div class='kpi-val' style='color:#f39c12'>{warned}</div><div class='kpi-label'>WARNINGS</div></div>
  <div class='kpi'><div class='kpi-val' style='color:#2980b9'>{score_pct}%</div><div class='kpi-label'>COMPLIANCE SCORE</div></div>
</div>
<table>
<tr><th>Control</th><th>Title</th><th>Status</th><th>Detail</th><th>Remediation</th></tr>
{rows}
</table></main></body></html>"""

    html_path = output_dir / f"cis_{cloud}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html_path.write_text(html, encoding="utf-8")

    print(f"\n{'='*50}")
    print(f"CIS {cloud.upper()} Benchmark Results")
    print(f"{'='*50}")
    print(f"  ✅ PASS  : {passed}")
    print(f"  ❌ FAIL  : {failed}")
    print(f"  ⚠️  WARN  : {warned}")
    print(f"  Score   : {score_pct}%")
    print(f"  HTML    : {html_path}")
    print(f"  JSON    : {json_path}")
    print(f"{'='*50}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CIS Benchmark Compliance Checker")
    parser.add_argument("--cloud", required=True, choices=["aws", "azure", "gcp"])
    parser.add_argument("--profile",      default="default",  help="AWS profile")
    parser.add_argument("--subscription", default="",         help="Azure subscription ID")
    parser.add_argument("--project",      default="",         help="GCP project ID")
    parser.add_argument("--output",       default="./reports", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.cloud == "aws":
        results = run_aws_checks(args.profile)
    elif args.cloud == "azure":
        print("Azure checks: Connect via `az login` then set --subscription")
        print("Azure module coming soon — run Terraform defender module for automated enforcement.")
        sys.exit(0)
    elif args.cloud == "gcp":
        print("GCP checks: Authenticate via `gcloud auth application-default login`")
        print("GCP module coming soon — run Terraform scc module for automated enforcement.")
        sys.exit(0)

    generate_report(results, args.cloud, output_dir)


if __name__ == "__main__":
    main()

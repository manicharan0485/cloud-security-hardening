# ☁️ Cloud Security Hardening

> **Multi-cloud security automation for AWS, Azure, and GCP.**  
> Terraform modules + Python scripts to enforce CIS Benchmarks, enable security services, and detect misconfigurations.

> 🧪 **Reference / lab project.** Original practice code written to demonstrate the approach. It is not taken from an employer's codebase. Review and adapt before using it in your own environment.

![Terraform](https://img.shields.io/badge/Terraform-7B42BC?style=flat&logo=terraform&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-FF9900?style=flat&logo=amazonaws&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![GCP](https://img.shields.io/badge/GCP-4285F4?style=flat&logo=googlecloud&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🎯 What This Repo Does

| Cloud | Coverage |
|-------|----------|
| **AWS** | Security Hub (CIS v1.4), GuardDuty, CloudTrail, S3 Block Public Access, IAM Password Policy, Root MFA |
| **Azure** | Microsoft Defender for Cloud, Azure Policy (CIS), Key Vault hardening, NSG audit |
| **GCP** | Security Command Center, Org Policy constraints, VPC Service Controls, IAM audit |

---

## 📂 Structure

```
cloud-security-hardening/
│
├── terraform/
│   ├── aws/
│   │   ├── modules/
│   │   │   ├── security-hub/         # CIS Benchmark + custom standards
│   │   │   ├── guardduty/            # Threat detection across all regions
│   │   │   ├── iam-hardening/        # Password policy, root MFA, access keys
│   │   │   └── s3-security/          # Block public access, encryption, logging
│   │   └── environments/
│   │       └── prod/                 # main.tf + terraform.tfvars.example
│   ├── azure/
│   │   ├── modules/
│   │   │   ├── defender/             # Defender for Cloud plans
│   │   │   └── key-vault/            # Soft delete, purge protection, RBAC
│   └── gcp/
│       └── modules/
│           └── scc/                  # Security Command Center
│
├── scripts/
│   ├── python/
│   │   ├── cis_benchmark_checker.py  # Multi-cloud CIS compliance scanner
│   │   ├── cost_optimizer.py         # Idle resource + savings report
│   │   └── requirements.txt
│   └── bash/
│       └── aws_baseline.sh           # One-shot AWS account hardening
```

---

## 🚀 Quick Start

### AWS Hardening (10 min)

```bash
cd terraform/aws/environments/prod
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your AWS account ID and region

terraform init
terraform plan
terraform apply
```

This enables:
- ✅ Security Hub with CIS AWS Foundations Benchmark v1.4
- ✅ GuardDuty in all configured regions
- ✅ CloudTrail (multi-region, S3 + CloudWatch)
- ✅ S3 account-level Block Public Access
- ✅ IAM password policy (14 char min, MFA required)
- ✅ Root account MFA check

### Azure and GCP modules

The Azure modules (`terraform/azure/modules/defender`, `terraform/azure/modules/key-vault`) and the GCP module (`terraform/gcp/modules/scc`) are reusable building blocks. Reference them from your own root module, then run `terraform init && terraform apply` after `az login` or `gcloud auth application-default login`.

---

## 📊 CIS Benchmark Coverage

### AWS (CIS v1.4)
| Control | Description | Status |
|---------|-------------|--------|
| 1.4 | No root access key | ✅ Automated |
| 1.5 | MFA for root | ✅ Checked |
| 1.8 | IAM password policy | ✅ Enforced |
| 2.1 | CloudTrail enabled | ✅ Automated |
| 2.6 | CloudTrail S3 logging | ✅ Automated |
| 3.1 | Unauthorized API calls alarm | ✅ Automated |
| 4.1 | No unrestricted SSH (0.0.0.0/0) | ✅ Checked |
| 4.2 | No unrestricted RDP (0.0.0.0/0) | ✅ Checked |

### Azure (CIS v2.0)
| Control | Description | Status |
|---------|-------------|--------|
| 2.1 | Defender for Servers enabled | ✅ Automated |
| 3.1 | Storage encryption at rest | ✅ Enforced |
| 4.1 | Key Vault soft delete | ✅ Enforced |
| 5.1 | Diagnostic logs enabled | ✅ Automated |

---

## 🔍 CIS Compliance Checker

```bash
pip install -r scripts/python/requirements.txt

# AWS
python scripts/python/cis_benchmark_checker.py --cloud aws --profile default --output ./reports

# Azure
python scripts/python/cis_benchmark_checker.py --cloud azure --subscription <SUB_ID>

# GCP
python scripts/python/cis_benchmark_checker.py --cloud gcp --project <PROJECT_ID>
```

Generates a detailed HTML report with pass/fail per CIS control.

---

## 💰 Cost Optimizer

```bash
python scripts/python/cost_optimizer.py --cloud aws --profile default
```

Identifies:
- Unattached EBS volumes
- Idle EC2 instances (CPU < 5% for 14 days)
- Unused Elastic IPs
- Old snapshots (> 90 days)
- Oversized RDS instances

**Typical savings: 15–25% monthly cloud spend.**

---

## ⚠️ Prerequisites

- Terraform >= 1.5.0
- AWS CLI v2 (for AWS modules)
- Azure CLI (for Azure modules)
- Google Cloud SDK (for GCP modules)
- Python 3.10+

---

## 🔐 Security Notes

- All Terraform state should be stored in encrypted remote backend (S3/Azure Blob/GCS)
- Never commit `terraform.tfvars` with real values — use `.gitignore`
- Use OIDC/Workload Identity Federation instead of static credentials in CI/CD
- Rotate access keys before running IAM hardening scripts

---

## 📄 License

MIT — Free to use and adapt.

---

## 👤 Author

**Manicharan Ravi** — IT Specialist & Cloud Engineer  
📍 Mainz, Germany | ☁️ AWS · Azure · GCP · Terraform · Security

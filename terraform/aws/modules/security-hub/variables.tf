variable "prefix" {
  description = "Resource name prefix (e.g., 'prod', 'mycompany')"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "kms_key_id" {
  description = "KMS key ID for SNS encryption. Leave empty for AWS-managed key."
  type        = string
  default     = ""
}

variable "alert_email" {
  description = "Email address for CRITICAL/HIGH finding alerts. Leave empty to skip."
  type        = string
  default     = ""
}

variable "enable_nist" {
  description = "Enable NIST SP 800-53 Rev 5 standard (additional cost)"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

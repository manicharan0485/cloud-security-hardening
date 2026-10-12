# ─────────────────────────────────────────────────────────────────────────────
# Module: gcp/modules/scc
# Purpose: Enable Google Cloud Security Command Center (SCC) with built-in
#          security sources and notification feeds.
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

# ─── SCC Notification config (high-severity findings → Pub/Sub) ──────────────

resource "google_pubsub_topic" "scc_findings" {
  name    = "${var.prefix}-scc-findings"
  project = var.project_id

  labels = var.labels
}

resource "google_pubsub_subscription" "scc_findings" {
  name    = "${var.prefix}-scc-findings-sub"
  topic   = google_pubsub_topic.scc_findings.name
  project = var.project_id

  ack_deadline_seconds       = 20
  message_retention_duration = "604800s"  # 7 days

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

resource "google_scc_notification_config" "high_severity" {
  config_id    = "${var.prefix}-high-severity"
  organization = var.organization_id
  description  = "Send HIGH and CRITICAL SCC findings to Pub/Sub"
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = "severity = \"HIGH\" OR severity = \"CRITICAL\""
  }
}

# ─── Org-level IAM audit logging (CIS 2.1) ───────────────────────────────────

resource "google_organization_iam_audit_config" "all_services" {
  org_id  = var.organization_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# ─── Org policy: Disable service account key creation ────────────────────────

resource "google_organization_policy" "disable_sa_key_creation" {
  org_id     = var.organization_id
  constraint = "iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }
}

# ─── Org policy: Restrict public Cloud Storage buckets ───────────────────────

resource "google_organization_policy" "no_public_gcs" {
  org_id     = var.organization_id
  constraint = "storage.uniformBucketLevelAccess"

  boolean_policy {
    enforced = true
  }
}

# ─── Org policy: Require OS Login on compute ─────────────────────────────────

resource "google_organization_policy" "require_os_login" {
  org_id     = var.organization_id
  constraint = "compute.requireOsLogin"

  boolean_policy {
    enforced = true
  }
}

# ─── Org policy: Disable default network in new projects ─────────────────────

resource "google_organization_policy" "skip_default_network" {
  org_id     = var.organization_id
  constraint = "compute.skipDefaultNetworkCreation"

  boolean_policy {
    enforced = true
  }
}

# ─── Log sink: send audit logs to BigQuery ───────────────────────────────────

resource "google_bigquery_dataset" "audit_logs" {
  dataset_id    = replace("${var.prefix}_audit_logs", "-", "_")
  friendly_name = "Security Audit Logs"
  location      = var.location
  project       = var.project_id

  delete_contents_on_destroy = false
  default_table_expiration_ms = 7776000000  # 90 days in ms

  labels = var.labels
}

resource "google_logging_organization_sink" "audit_bq" {
  name             = "${var.prefix}-audit-bq-sink"
  org_id           = var.organization_id
  destination      = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.audit_logs.dataset_id}"
  include_children = true

  filter = "logName:(cloudaudit.googleapis.com/activity OR cloudaudit.googleapis.com/data_access)"
}

resource "google_bigquery_dataset_iam_member" "sink_writer" {
  dataset_id = google_bigquery_dataset.audit_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_organization_sink.audit_bq.writer_identity
  project    = var.project_id
}

# ─── Outputs ─────────────────────────────────────────────────────────────────

output "pubsub_topic"        { value = google_pubsub_topic.scc_findings.name }
output "audit_dataset_id"    { value = google_bigquery_dataset.audit_logs.dataset_id }

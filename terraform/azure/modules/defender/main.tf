# ─────────────────────────────────────────────────────────────────────────────
# Module: azure/modules/defender
# Purpose: Enable Microsoft Defender for Cloud across all relevant resource 
#          types and configure security contact + auto-provisioning.
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.75"
    }
  }
}

# ─── Defender plans ──────────────────────────────────────────────────────────

locals {
  defender_plans = [
    "VirtualMachines",
    "SqlServers",
    "AppServices",
    "StorageAccounts",
    "Containers",
    "KeyVaults",
    "Dns",
    "Arm",
  ]
}

resource "azurerm_security_center_subscription_pricing" "plans" {
  for_each      = toset(local.defender_plans)
  resource_type = each.value
  tier          = "Standard"
}

# ─── Auto-provisioning: Log Analytics agent ───────────────────────────────────

resource "azurerm_security_center_auto_provisioning" "mma" {
  auto_provision = "On"
}

# ─── Security contact ────────────────────────────────────────────────────────

resource "azurerm_security_center_contact" "main" {
  email               = var.security_contact_email
  phone               = var.security_contact_phone
  alert_notifications = true
  alerts_to_admins    = true
}

# ─── Log Analytics workspace for Defender ────────────────────────────────────

resource "azurerm_log_analytics_workspace" "security" {
  name                = "${var.prefix}-security-workspace"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 90

  tags = var.tags
}

resource "azurerm_security_center_workspace" "main" {
  scope        = "/subscriptions/${var.subscription_id}"
  workspace_id = azurerm_log_analytics_workspace.security.id
}

# ─── Azure Activity Log → Log Analytics ──────────────────────────────────────

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "${var.prefix}-activity-log"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Alert"
  }
  enabled_log {
    category = "Policy"
  }
}

# ─── Azure Policy: CIS Microsoft Azure Foundations Benchmark ─────────────────

data "azurerm_policy_set_definition" "cis" {
  display_name = "CIS Microsoft Azure Foundations Benchmark v2.0.0"
}

resource "azurerm_subscription_policy_assignment" "cis" {
  name                 = "${var.prefix}-cis-benchmark"
  subscription_id      = "/subscriptions/${var.subscription_id}"
  policy_definition_id = data.azurerm_policy_set_definition.cis.id
  display_name         = "CIS Azure Foundations Benchmark v2.0"
  description          = "Assigns the CIS Azure Foundations Benchmark policy initiative"

  identity {
    type = "SystemAssigned"
  }

  location = var.location
}

# ─── Outputs ─────────────────────────────────────────────────────────────────

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.security.id
}

output "log_analytics_workspace_name" {
  value = azurerm_log_analytics_workspace.security.name
}

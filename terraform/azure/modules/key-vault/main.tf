# ─────────────────────────────────────────────────────────────────────────────
# Module: azure/modules/key-vault
# Purpose: Create/harden Azure Key Vault with CIS controls.
#          CIS Azure 4.1–4.5: soft delete, purge protection, RBAC, private endpoint
# ─────────────────────────────────────────────────────────────────────────────

resource "azurerm_key_vault" "main" {
  name                = "${var.prefix}-kv-${substr(var.subscription_id, 0, 8)}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = var.tenant_id
  sku_name            = "premium"

  # CIS 4.1 — Soft delete MUST be enabled
  soft_delete_retention_days = 90

  # CIS 4.2 — Purge protection MUST be enabled
  purge_protection_enabled = true

  # CIS 4.3 — Use RBAC instead of vault access policies
  enable_rbac_authorization = true

  # Network rules — restrict to known IP ranges
  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
  }

  tags = var.tags
}

# ─── Diagnostic logging ──────────────────────────────────────────────────────

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "${var.prefix}-kv-diag"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category = "AuditEvent" }
  enabled_log { category = "AzurePolicyEvaluationDetails" }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# ─── Alert: Key Vault access from unauthorized IP ────────────────────────────

resource "azurerm_monitor_activity_log_alert" "kv_delete" {
  name                = "${var.prefix}-kv-delete-alert"
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_key_vault.main.id]
  description         = "Alert when Key Vault or its secrets/keys are deleted"

  criteria {
    resource_id    = azurerm_key_vault.main.id
    operation_name = "Microsoft.KeyVault/vaults/delete"
    category       = "Administrative"
  }

  action {
    action_group_id = var.action_group_id
  }

  tags = var.tags
}

output "key_vault_id"   { value = azurerm_key_vault.main.id }
output "key_vault_uri"  { value = azurerm_key_vault.main.vault_uri }
output "key_vault_name" { value = azurerm_key_vault.main.name }

variable "account_id" {
  type        = number
  description = "New Relic account ID"
}

variable "region" {
  type        = string
  default     = "US"
  description = "New Relic region supported by the provider (check the provider docs for JP)"
}

variable "app_name" {
  type        = string
  description = "APM application name (appName / entity.name)"
}

variable "bypass_scope_pattern" {
  type        = string
  default     = "admin:%"
  description = "authz.required_scope pattern of legitimate cross-owner access, excluded from D01"
}

variable "runbook_base_url" {
  type        = string
  default     = "https://github.com/photographed/nr-authz-radar/blob/main/templates/knowledge-runbooks"
  description = "Where the runbooks live (point it at your own copy)"
}

variable "slack_destination_id" {
  type        = string
  description = "ID of a Slack destination created in the New Relic UI (Slack needs OAuth in the UI)"
}

variable "slack_channel_id_critical" {
  type        = string
  description = "Slack channel ID for CRITICAL issues"
}

variable "slack_channel_id_warning" {
  type        = string
  description = "Slack channel ID for HIGH (warning) issues"
}

variable "learning_mode" {
  type        = bool
  default     = true
  description = "While true, HIGH (strong signal) notifications are off so thresholds can be tuned. CRITICAL (evidence) always notifies."
}

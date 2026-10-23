resource "newrelic_alert_policy" "authz_radar" {
  name                = "[authz-radar] ${var.app_name}"
  incident_preference = "PER_CONDITION_AND_TARGET"
}

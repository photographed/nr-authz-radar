# CRITICAL = evidence-level detections only (shared/detections.json): its own channel, and
#   Workflow Automation / Autopilot (templates/workflow-automation). Pages from day one.
# HIGH = strong signals: a quieter channel, no Autopilot. Muted while learning_mode = true,
#   so thresholds can be tuned before anyone is notified.
# Anomalies live in a separate policy that no workflow points at (gen_alerts.py --include-anomaly).

resource "newrelic_notification_channel" "slack_critical" {
  account_id     = var.account_id
  name           = "[authz-radar] critical"
  type           = "SLACK"
  destination_id = var.slack_destination_id
  product        = "IINT"

  property {
    key   = "channelId"
    value = var.slack_channel_id_critical
  }
}

resource "newrelic_notification_channel" "slack_warning" {
  account_id     = var.account_id
  name           = "[authz-radar] warning"
  type           = "SLACK"
  destination_id = var.slack_destination_id
  product        = "IINT"

  property {
    key   = "channelId"
    value = var.slack_channel_id_warning
  }
}

resource "newrelic_workflow" "critical" {
  name                  = "[authz-radar] critical"
  muting_rules_handling = "NOTIFY_ALL_ISSUES"

  issues_filter {
    name = "authz-radar critical"
    type = "FILTER"

    predicate {
      attribute = "labels.policyIds"
      operator  = "EXACTLY_MATCHES"
      values    = [newrelic_alert_policy.authz_radar.id]
    }

    predicate {
      attribute = "priority"
      operator  = "EQUAL"
      values    = ["CRITICAL"]
    }
  }

  destination {
    channel_id = newrelic_notification_channel.slack_critical.id
  }
}

resource "newrelic_workflow" "warning" {
  name                  = "[authz-radar] warning"
  enabled               = !var.learning_mode
  muting_rules_handling = "NOTIFY_ALL_ISSUES"

  issues_filter {
    name = "authz-radar warning"
    type = "FILTER"

    predicate {
      attribute = "labels.policyIds"
      operator  = "EXACTLY_MATCHES"
      values    = [newrelic_alert_policy.authz_radar.id]
    }

    predicate {
      attribute = "priority"
      operator  = "EQUAL"
      values    = ["HIGH"]
    }
  }

  destination {
    channel_id = newrelic_notification_channel.slack_warning.id
  }
}

terraform {
  required_version = ">= 1.5"
  required_providers {
    newrelic = {
      source  = "newrelic/newrelic"
      version = "~> 3.0"
    }
  }
}

# The API key comes from the NEW_RELIC_API_KEY environment variable (a User key).
provider "newrelic" {
  account_id = var.account_id
  region     = var.region
}

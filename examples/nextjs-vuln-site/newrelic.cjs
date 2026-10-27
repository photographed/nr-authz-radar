'use strict'
// Optional. Use only to send data to your own New Relic account:
//   NEW_RELIC_LICENSE_KEY=... NODE_OPTIONS='-r @newrelic/next' npm start
// (install @newrelic/next and newrelic first). The demo works without this file.
exports.config = {
  app_name: [process.env.NEW_RELIC_APPNAME || 'nextjs-vuln-site'],
  license_key: process.env.NEW_RELIC_LICENSE_KEY,
  logging: { level: 'info' },
  distributed_tracing: { enabled: true },
  application_logging: { forwarding: { enabled: true } }
}

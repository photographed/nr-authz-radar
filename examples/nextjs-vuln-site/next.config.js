// Local demo only. Never deploy.
/** @type {import('next').NextConfig} */
module.exports = {
  // The nr-authz-radar helper is CommonJS; keep it external so it is required at runtime
  // (so a real New Relic agent, loaded with `-r @newrelic/next`, can see the same module instance).
  serverExternalPackages: ['@nr-authz-radar/node', 'newrelic']
}

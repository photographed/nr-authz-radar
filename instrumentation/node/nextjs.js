'use strict'
// nr-authz-radar for Next.js (App Router Route Handlers, Pages API routes, Server Actions).
//
// Where New Relic can see this (agent via `-r @newrelic/next`):
//   - Route Handlers (app/**/route.ts), Pages API routes (pages/api/**), Server Actions: these run
//     in the Node runtime inside a transaction, so custom attributes attach. USE THIS HELPER THERE.
//   - middleware.ts runs on the EDGE runtime: the Node agent is NOT loaded, nothing is recorded.
//     Do the owner check in the route/handler, not only in middleware.
//   - Client components and build-time code: no server telemetry.
//
// Attributes and rules: shared/attribute-spec.md. Pseudonyms match the other languages.
const { AsyncLocalStorage } = require('node:async_hooks')
const ar = require('./authz-radar')

const als = new AsyncLocalStorage()
const REASONS = ['owner_mismatch', 'scope_missing', 'role_missing', 'tenant_mismatch', 'unauthenticated']

// Used when no New Relic agent is loaded (no `-r @newrelic/next`): every call is a safe no-op, so
// the app and the decision-log fallback keep working without the agent.
const NOOP = { addCustomAttribute () {}, setUserID () {}, noticeError () {} }

function env (name, fallback) {
  const v = typeof process !== 'undefined' && process.env ? process.env[name] : undefined
  return v === undefined || v === '' ? fallback : v
}

function agent (nr) {
  if (nr) return nr
  try { return require('newrelic') } catch { return NOOP } // no agent loaded: do nothing, never throw
}

function token (v) {
  if (v === undefined || v === null || String(v).trim() === '') return '-'
  return String(v).replace(/\s+/g, '_').slice(0, 64)
}

// The fixed decision log line (shared/attribute-spec.md). No user / resource / IP values.
function decisionLine (decision, ownerMatch, reason, resourceType, operation, bypass) {
  let line = `authz-radar decision=${token(decision)} owner_match=${ownerMatch === null ? '-' : ownerMatch}` +
    ` reason=${token(reason)} resource.type=${token(resourceType)} api.operation=${token(operation)}`
  if (bypass) line += ` bypass=${token(bypass)}`
  return line
}

function resolveConfig (opts = {}) {
  const attributes = opts.attributes || env('AUTHZ_RADAR_ATTRIBUTES', 'minimal')
  return {
    nr: agent(opts.nr),
    key: opts.key !== undefined ? opts.key : env('AUTHZ_RADAR_HMAC_KEY', ''),
    full: attributes === 'full',
    enforce: opts.enforce !== undefined ? opts.enforce : env('AUTHZ_RADAR_OWNERSHIP_MODE', 'enforce') !== 'observe',
    denyStatus: opts.denyStatus || 404,
    log: opts.log || (String(env('AUTHZ_RADAR_LOG_DECISIONS', 'false')) === 'true' ? (l) => console.log(l) : null),
    state: ar.newState(),
    operations: new Set(),
    resourceType: null,
    loggedMismatch: false
  }
}

function store () {
  const s = als.getStore()
  if (!s) throw new Error('nr-authz-radar: call setUser/ownership inside withAuthzRadar()')
  return s
}

// Wrap an App Router Route Handler / Pages API handler / Server Action. Sets up per-request state,
// and turns an OwnershipError into a Response (App Router) or re-throws for the caller to handle.
function withAuthzRadar (handler, opts = {}) {
  return function (...args) {
    const s = resolveConfig(opts)
    return als.run(s, async () => {
      try {
        return await handler(...args)
      } catch (e) {
        if (e instanceof ar.OwnershipError) {
          // the deny was already recorded in ownership(); answer without leaking existence
          if (typeof Response !== 'undefined' && opts.rethrow !== true) {
            return new Response(null, { status: s.denyStatus })
          }
        }
        throw e
      }
    })
  }
}

function setUser (userId) {
  const s = store()
  const value = ar.pseudonym(userId, s.key) // null without a key (a plain hash can be brute-forced)
  if (value) s.nr.setUserID(value)
}

// Call right after loading a resource by a client-supplied id.
function ownership (ownerId, currentUserId, { resourceType = null, bypassScope = null } = {}) {
  const s = store()
  if (resourceType) {
    s.resourceType = resourceType
    if (s.full && s.nr) s.nr.addCustomAttribute('resource.type', resourceType)
  }
  const logOnce = (line) => { if (s.log && !s.loggedMismatch) { s.loggedMismatch = true; s.log(line) } }
  try {
    const match = ar.checkOwnership(ownerId, currentUserId, s.state, {
      enforce: !bypassScope && s.enforce, bypassScope, nr: s.nr
    })
    if (!match) {
      // let through: observe mode, or a bypass scope. This is the D01 shape (or its excluded case).
      logOnce(decisionLine('allow', false, null, s.resourceType, operation(s), bypassScope))
    }
    return match
  } catch (e) {
    if (e instanceof ar.OwnershipError) {
      logOnce(decisionLine('deny', false, 'owner_mismatch', s.resourceType, operation(s)))
    }
    throw e
  }
}

// api.protocol / server-side api.operation (shared/protocols.md). Never the client-supplied name.
function protocol (proto, operation) {
  const s = store()
  if (s.nr) s.nr.addCustomAttribute('api.protocol', proto)
  if (!operation) return
  s.operations.add(operation)
  const ops = [...s.operations].sort()
  if (s.nr) s.nr.addCustomAttribute('api.operation', ops.length > 3 ? ops.slice(0, 3).join(',') + ',…' : ops.join(','))
}

function operation (s) {
  return s.operations.size ? [...s.operations].sort().join(',') : null
}

// Record a deny that no ownership() call produced (e.g. a 401/403 from your auth check).
function deny (reason) {
  const s = store()
  const first = s.state.decision !== 'deny'
  s.state.decision = 'deny'
  if (s.nr) s.nr.addCustomAttribute('authz.decision', 'deny')
  if (reason && REASONS.includes(reason) && s.full && s.nr) s.nr.addCustomAttribute('authz.deny_reason', reason)
  if (first && s.log) s.log(decisionLine('deny', s.state.mismatch ? false : null, reason, s.resourceType, operation(s)))
}

module.exports = { withAuthzRadar, setUser, ownership, protocol, deny, decisionLine, OwnershipError: ar.OwnershipError, pseudonym: ar.pseudonym }

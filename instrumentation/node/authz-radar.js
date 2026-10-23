'use strict'
// nr-authz-radar stage S2 for Node.js (newrelic agent 14.x API).
// Sends resource.owner_match and authz.decision (shared/attribute-spec.md) and a pseudonymized enduser.id.
// Call checkOwnership() right after loading a resource by a client-supplied ID.
const crypto = require('node:crypto')

class OwnershipError extends Error {
  constructor () {
    super('ownership check failed')
    this.name = 'OwnershipError'
    this.status = 403 // map to 403 (or 404)
  }
}

function agent (nr) {
  return nr || require('newrelic') // lazy: the module also loads without the agent
}

// 'u_' + 16 hex chars. Without a key nothing is sent (a plain hash can be brute-forced).
function pseudonym (userId, key) {
  if (!key || userId === undefined || userId === null) return null
  return 'u_' + crypto.createHmac('sha256', key).update(String(userId)).digest('hex').slice(0, 16)
}

function setUser (userId, key, nr) {
  const value = pseudonym(userId, key)
  if (value) agent(nr).setUserID(value)
}

// One state object per request (e.g. res.locals.authzRadar = newState()).
function newState () {
  return { mismatch: false, denied: false }
}

// enforce=false (observe) lets mismatches through so detection D01 shows real IDORs.
// bypassScope marks legitimate cross-owner access (e.g. 'admin:read') so D01 excludes it.
function checkOwnership (ownerId, currentUserId, state, { enforce = true, bypassScope = null, nr } = {}) {
  const api = agent(nr)
  const match = currentUserId !== undefined && currentUserId !== null && String(ownerId) === String(currentUserId)
  if (!match) state.mismatch = true
  api.addCustomAttribute('resource.owner_match', !state.mismatch)
  if (!match && bypassScope) {
    api.addCustomAttribute('authz.required_scope', bypassScope)
  } else if (!match && enforce) {
    state.denied = true
    api.addCustomAttribute('authz.decision', 'deny')
    const err = new OwnershipError()
    api.noticeError(err, {}, true) // expected: grouped in Errors Inbox, not counted in error rate
    throw err
  }
  if (!state.denied) api.addCustomAttribute('authz.decision', 'allow')
  return match
}

module.exports = { OwnershipError, pseudonym, setUser, newState, checkOwnership }

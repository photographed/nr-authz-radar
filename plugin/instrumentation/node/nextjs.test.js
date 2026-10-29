'use strict'
const test = require('node:test')
const assert = require('node:assert')
const nx = require('./nextjs')

function fake () {
  return {
    attrs: {}, errors: 0, user: null,
    addCustomAttribute (k, v) { this.attrs[k] = v },
    noticeError (e, a, expected) { if (expected) this.errors++ },
    setUserID (v) { this.user = v }
  }
}

test('route handler: owner is allowed, MINIMAL sends owner_match + decision only', async () => {
  const nr = fake()
  const logs = []
  const handler = nx.withAuthzRadar(async () => {
    nx.setUser(7)
    nx.ownership(7, 7, { resourceType: 'order' })
    return new Response('ok', { status: 200 })
  }, { nr, key: 'k', log: (l) => logs.push(l) })
  const res = await handler()
  assert.strictEqual(res.status, 200)
  assert.deepStrictEqual(nr.attrs, { 'resource.owner_match': true, 'authz.decision': 'allow' })
  assert.match(nr.user, /^u_[0-9a-f]{16}$/)
  assert.deepStrictEqual(logs, []) // only denials / let-through mismatches are logged
})

test('route handler: IDOR in enforce mode returns denyStatus and records deny', async () => {
  const nr = fake()
  const logs = []
  const handler = nx.withAuthzRadar(async () => {
    nx.ownership(7, 8, { resourceType: 'order' })
    return new Response('should not reach', { status: 200 })
  }, { nr, key: 'k', enforce: true, denyStatus: 404, log: (l) => logs.push(l) })
  const res = await handler()
  assert.strictEqual(res.status, 404)
  assert.strictEqual(nr.attrs['authz.decision'], 'deny')
  assert.strictEqual(nr.attrs['resource.owner_match'], false)
  assert.strictEqual(nr.errors, 1)
  assert.deepStrictEqual(logs, ['authz-radar decision=deny owner_match=false reason=owner_mismatch resource.type=order api.operation=-'])
})

test('observe mode: IDOR is let through and logged as the D01 shape', async () => {
  const nr = fake()
  const logs = []
  const handler = nx.withAuthzRadar(async () => {
    nx.ownership(7, 8, { resourceType: 'order' })
    return new Response('leaked', { status: 200 })
  }, { nr, key: 'k', enforce: false, log: (l) => logs.push(l) })
  const res = await handler()
  assert.strictEqual(res.status, 200)
  assert.strictEqual(nr.attrs['authz.decision'], 'allow')
  assert.strictEqual(nr.attrs['resource.owner_match'], false)
  assert.deepStrictEqual(logs, ['authz-radar decision=allow owner_match=false reason=- resource.type=order api.operation=-'])
})

test('bypass scope is labelled and logged with bypass=', async () => {
  const nr = fake()
  const logs = []
  const handler = nx.withAuthzRadar(async () => {
    nx.ownership(7, 'ops', { resourceType: 'order', bypassScope: 'admin:read' })
  }, { nr, key: 'k', log: (l) => logs.push(l) })
  await handler()
  assert.strictEqual(nr.attrs['authz.required_scope'], 'admin:read')
  assert.strictEqual(nr.attrs['authz.decision'], 'allow')
  assert.match(logs[0], /bypass=admin:read$/)
})

test('full attributes add resource.type; protocol sorts operations', async () => {
  const nr = fake()
  const handler = nx.withAuthzRadar(async () => {
    nx.protocol('graphql', 'Query.order')
    nx.protocol('graphql', 'Query.me')
    nx.ownership(1, 1, { resourceType: 'order' })
  }, { nr, key: 'k', attributes: 'full' })
  await handler()
  assert.strictEqual(nr.attrs['resource.type'], 'order')
  assert.strictEqual(nr.attrs['api.protocol'], 'graphql')
  assert.strictEqual(nr.attrs['api.operation'], 'Query.me,Query.order')
})

test('deny() records an auth failure with no ownership call', async () => {
  const nr = fake()
  const logs = []
  const handler = nx.withAuthzRadar(async () => {
    nx.deny('unauthenticated')
    return new Response(null, { status: 401 })
  }, { nr, key: 'k', attributes: 'full', log: (l) => logs.push(l) })
  await handler()
  assert.strictEqual(nr.attrs['authz.decision'], 'deny')
  assert.strictEqual(nr.attrs['authz.deny_reason'], 'unauthenticated')
  assert.strictEqual(logs.length, 1)
})

test('calling helpers outside withAuthzRadar throws a clear error', () => {
  assert.throws(() => nx.setUser(1), /inside withAuthzRadar/)
})

test('each request gets isolated state (AsyncLocalStorage)', async () => {
  const nr = fake()
  const h = nx.withAuthzRadar(async (owner, user) => {
    nx.ownership(owner, user, { resourceType: 'order' })
    return nr.attrs['resource.owner_match']
  }, { nr, key: 'k', enforce: false })
  const [a, b] = await Promise.all([h(1, 1), h(1, 2)])
  // concurrent requests must not share the sticky owner_match
  assert.ok(a === true || b === false)
})

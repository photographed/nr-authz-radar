'use strict'
const test = require('node:test')
const assert = require('node:assert')
const ar = require('./authz-radar')

function fake () {
  return {
    attrs: {}, errors: 0, user: null,
    addCustomAttribute (k, v) { this.attrs[k] = v },
    noticeError (e, a, expected) { if (expected) this.errors++ },
    setUserID (v) { this.user = v }
  }
}

test('owner is allowed', () => {
  const nr = fake()
  assert.strictEqual(ar.checkOwnership('alice', 'alice', ar.newState(), { nr }), true)
  assert.deepStrictEqual(nr.attrs, { 'resource.owner_match': true, 'authz.decision': 'allow' })
})

test('mismatch is denied in enforce mode', () => {
  const nr = fake()
  assert.throws(() => ar.checkOwnership('bob', 'alice', ar.newState(), { nr }), ar.OwnershipError)
  assert.deepStrictEqual(nr.attrs, { 'resource.owner_match': false, 'authz.decision': 'deny' })
  assert.strictEqual(nr.errors, 1)
})

test('observe mode records the D01 shape and owner_match is sticky', () => {
  const nr = fake()
  const s = ar.newState()
  ar.checkOwnership('bob', 'alice', s, { enforce: false, nr })
  ar.checkOwnership('alice', 'alice', s, { enforce: false, nr })
  assert.deepStrictEqual(nr.attrs, { 'resource.owner_match': false, 'authz.decision': 'allow' })
})

test('bypass is labelled', () => {
  const nr = fake()
  ar.checkOwnership('bob', 'ops', ar.newState(), { bypassScope: 'admin:read', nr })
  assert.strictEqual(nr.attrs['authz.required_scope'], 'admin:read')
  assert.strictEqual(nr.attrs['authz.decision'], 'allow')
})

test('user is pseudonymized and needs a key', () => {
  const nr = fake()
  ar.setUser('alice', 'k', nr)
  assert.match(nr.user, /^u_[0-9a-f]{16}$/)
  assert.strictEqual(ar.pseudonym('alice', ''), null)
})


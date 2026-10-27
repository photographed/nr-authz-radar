// In-memory demo data. Local test fixture only.
const users = {
  'token-alice': { id: 1, name: 'Alice', admin: false },
  'token-bob': { id: 2, name: 'Bob', admin: false },
  'token-admin': { id: 3, name: 'Admin', admin: true }
}
const orders = {
  1: { id: 1, user_id: 1, item: 'Keyboard', amount: 4000 },
  2: { id: 2, user_id: 1, item: 'Mouse', amount: 2000 },
  3: { id: 3, user_id: 2, item: 'Monitor', amount: 30000 }
}

// Token from the Authorization: Bearer header or ?api_token=. Authentication is fine here;
// the deliberate bugs are in authorization.
function userFromRequest (request) {
  const auth = request.headers.get('authorization') || ''
  const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : null
  const token = bearer || new URL(request.url).searchParams.get('api_token')
  return token ? users[token] || null : null
}

module.exports = { users, orders, userFromRequest }

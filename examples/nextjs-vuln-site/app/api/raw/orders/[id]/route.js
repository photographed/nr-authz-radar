// NOT instrumented: the same IDOR, with no authz telemetry. New Relic sees only 200 OK and cannot
// tell it apart from normal traffic (the "before"). Local test fixture only. Never deploy.
const { orders, userFromRequest } = require('../../../../../lib/data')

async function GET (request, { params }) {
  const user = userFromRequest(request)
  if (!user) return Response.json({ error: 'unauthenticated' }, { status: 401 })
  const { id } = await params
  const order = orders[id]
  if (!order) return Response.json({ error: 'not found' }, { status: 404 })
  return Response.json(order) // no owner check, nothing recorded
}

module.exports = { GET }

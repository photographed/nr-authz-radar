// INSTRUMENTED with nr-authz-radar. IDOR / BOLA (CWE-639): the handler loads any order by id.
// In observe mode the IDOR still happens (the point of the demo) but owner_match=false with
// decision=allow is recorded = detection D01. In enforce mode withAuthzRadar turns the thrown
// OwnershipError into a 404. Local test fixture only. Never deploy.
const { withAuthzRadar, setUser, ownership } = require('@nr-authz-radar/node/nextjs')
const { orders, userFromRequest } = require('../../../../lib/data')

async function handler (request, { params }) {
  const user = userFromRequest(request)
  if (!user) return Response.json({ error: 'unauthenticated' }, { status: 401 })
  setUser(user.id)

  const { id } = await params
  const order = orders[id]
  if (!order) return Response.json({ error: 'not found' }, { status: 404 })

  ownership(order.user_id, user.id, { resourceType: 'order' }) // compares order.user_id with the caller
  return Response.json(order)
}

const GET = withAuthzRadar(handler)
module.exports = { GET }

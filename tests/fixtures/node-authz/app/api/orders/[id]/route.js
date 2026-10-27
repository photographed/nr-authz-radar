// Next.js App Router file-based route (source only). Not run.
const { withAuthzRadar, setUser, ownership } = require('@nr-authz-radar/node/nextjs')

async function handler (request, { params }) {
  const user = await getUser(request)
  const { id } = await params
  const order = await db.loadOrder(id)
  ownership(order.user_id, user.id, { resourceType: 'order' })
  return Response.json(order)
}

const GET = withAuthzRadar(handler)
module.exports = { GET }

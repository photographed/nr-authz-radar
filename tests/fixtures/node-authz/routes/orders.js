// Express fixture (source only, intentionally mixed). Not run.
const express = require('express')
const router = express.Router()
const db = require('../db')

// IDOR: loads by id, no owner check. requireAuth is authentication only.
router.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.Order.findByPk(req.params.id)
  res.json(order)
})

// safe: scoped to the signed-in user
router.get('/api/orders/:id/receipt', requireAuth, async (req, res) => {
  const order = await db.Order.findOne({ where: { id: req.params.id, userId: req.user.id } })
  res.json(order)
})

// no auth middleware + SQL injection via template literal
router.get('/api/search', async (req, res) => {
  const q = req.query.q
  const rows = await db.sequelize.query(`SELECT id, item FROM orders WHERE item LIKE '%${q}%'`)
  res.json(rows)
})

// BFLA: admin action, no role check (only authenticated)
router.post('/api/admin/orders/:id/ship', requireAuth, async (req, res) => {
  await db.Order.update({ status: 'shipped' }, { where: { id: req.params.id } })
  res.json({ ok: true })
})

module.exports = router

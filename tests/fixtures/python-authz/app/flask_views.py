# Flask fixture (source only, intentionally mixed good/bad). Not run.
from flask import Blueprint, request, jsonify
from .models import Order, db

bp = Blueprint("orders", __name__)


@bp.route("/api/orders/<int:order_id>", methods=["GET"])
@login_required
def get_order(order_id):
    # IDOR: no owner check
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())


@bp.get("/api/orders/<int:order_id>/receipt")
@login_required
def get_receipt(order_id):
    # safe: filtered by current user
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
    return jsonify(order.to_dict())


@bp.get("/api/search")
def search():
    # no auth decorator at all + SQL injection via f-string
    q = request.args.get("q", "")
    rows = db.session.execute(f"SELECT id, item FROM orders WHERE item LIKE '%{q}%'")
    return jsonify([dict(r) for r in rows])

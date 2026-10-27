# FastAPI fixture (source only). Not run.
from fastapi import APIRouter, Depends
from .auth import current_user
from .models import Order

router = APIRouter()


@router.get("/api/v2/orders/{order_id}")
async def read_order(order_id: int, user=Depends(current_user)):
    # IDOR: loads by id, no owner comparison
    return await Order.get(order_id)


@router.post("/api/v2/admin/orders/{order_id}/ship")
async def ship(order_id: int):
    # BFLA: no auth dependency, no role check
    import subprocess
    subprocess.run(f"notify-ship {order_id}", shell=True)  # command injection too
    return {"status": "shipped"}

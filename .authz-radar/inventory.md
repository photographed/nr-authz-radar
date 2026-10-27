# Python endpoint inventory (7 endpoints, 5 to read)

Candidates only. Read the flagged handlers (file:line) to confirm. A path shown as `?` is
routed in `urls.py` (Django / DRF) — map it there. Being authenticated is not authorization.

| Endpoint | Handler | Authz | Flags | Location |
|---|---|---|---|---|
| `GET ?` | `OrderView.get` | yes | get_by_id | `tests/fixtures/python-authz/app/drf_views.py:10` |
| `POST ?` | `ImportView.post` | yes | unsafe_deserialization | `tests/fixtures/python-authz/app/drf_views.py:19` |
| `GET /api/v2/orders/{order_id}` | `read_order` | yes | — | `tests/fixtures/python-authz/app/fastapi_routes.py:10` |
| `POST /api/v2/admin/orders/{order_id}/ship` | `ship` | **none** | command_exec | `tests/fixtures/python-authz/app/fastapi_routes.py:16` |
| `GET /api/orders/<int:order_id>` | `get_order` | yes | get_by_id | `tests/fixtures/python-authz/app/flask_views.py:10` |
| `GET /api/orders/<int:order_id>/receipt` | `get_receipt` | yes | — | `tests/fixtures/python-authz/app/flask_views.py:18` |
| `GET /api/search` | `search` | **none** | sql_concat | `tests/fixtures/python-authz/app/flask_views.py:25` |

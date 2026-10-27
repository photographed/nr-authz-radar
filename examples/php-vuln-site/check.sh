#!/usr/bin/env bash
# Exercise the demo endpoints against a LOCAL server (default http://127.0.0.1:8000) to see what
# nr-authz-radar records. Every request is a plain authenticated API call; the point is that some
# of them are authorization violations the app should not allow. Local validation only.
set -u
BASE="${1:-http://127.0.0.1:8000}"
J=(-s -H "Accept: application/json")
code() { curl "${J[@]}" -o /dev/null -w "%{http_code}" "$@"; }

echo "Target: $BASE  (tokens: token-alice, token-bob, token-admin)"
echo
echo "1. Alice reads her own order 1        -> $(code "$BASE/api/orders/1?api_token=token-alice")  (expect 200, owner_match=true)"
echo "2. Alice reads Bob's order 3 (IDOR)   -> $(code "$BASE/api/orders/3?api_token=token-alice")  (observe: 200 but owner_match=false,decision=allow = D01; enforce: 404)"
echo "3. No token                           -> $(code "$BASE/api/orders/1")  (expect 401)"
echo "4. Non-admin Bob ships order 1 (BFLA) -> $(code -X PATCH "$BASE/api/orders/1/ship?api_token=token-bob")  (expect 200 = missing role check)"
echo "5. Raw IDOR, not instrumented         -> $(code "$BASE/api/raw/orders/3?api_token=token-alice")  (200, invisible to New Relic)"
echo "6. SQL injection, broken syntax       -> $(code "$BASE/api/raw/orders?api_token=token-alice&item=%27")  (500 = DB error feeds D06)"
echo
echo "Decision log lines (what detections D01 / L04 read):"
grep "authz-radar" storage/logs/laravel.log 2>/dev/null | tail -5 || echo "  (set AUTHZ_RADAR_LOG_DECISIONS=true and AUTHZ_RADAR_LOG_CHANNEL=single)"

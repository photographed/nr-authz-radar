#!/usr/bin/env bash
# Exercise the demo against a LOCAL server (default http://127.0.0.1:3000). Local validation only.
set -u
BASE="${1:-http://127.0.0.1:3000}"
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
echo "Target: $BASE  (tokens: token-alice, token-bob, token-admin)"
echo
echo "1. Alice reads her own order 1      -> $(code "$BASE/api/orders/1?api_token=token-alice")  (expect 200, owner_match=true)"
echo "2. Alice reads Bob's order 3 (IDOR) -> $(code "$BASE/api/orders/3?api_token=token-alice")  (observe: 200 + D01 log; enforce: 404)"
echo "3. No token                         -> $(code "$BASE/api/orders/1")  (expect 401)"
echo "4. Raw IDOR, not instrumented       -> $(code "$BASE/api/raw/orders/3?api_token=token-alice")  (200, invisible to New Relic)"
echo
echo "Look at the 'next start' / 'next dev' output for lines like:"
echo "  authz-radar decision=allow owner_match=false reason=- resource.type=order api.operation=-"

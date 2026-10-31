#!/usr/bin/env bash
# End-to-end demo check: the Docker demo must turn a loopback port scan into a High PortScan alert over the API.
# Run from the repo root. Never prints the dashboard token (CI logs are public).
set -euo pipefail
# Own project name: the teardown's `down -v` must never remove a local demo's data volume.
compose=(docker compose -p sentinelstream-e2e -f docker-compose.yml -f docker-compose.demo.yml)
trap '"${compose[@]}" down -v >/dev/null 2>&1' EXIT
fail() { echo "e2e: FAIL: $*" >&2; "${compose[@]}" logs --tail 40 backend >&2 || true; exit 1; }

"${compose[@]}" up --build -d
for _ in $(seq 60); do curl -fs http://127.0.0.1:8000/health >/dev/null && break; sleep 2; done
curl -fs http://127.0.0.1:8000/health >/dev/null || fail "backend not healthy after 120 s"

token=$("${compose[@]}" exec -T backend cat /app/data/api-token)
[ -n "$token" ] || fail "no dashboard token"

# The demo's simulator service runs one port scan as soon as the backend is healthy.
for _ in $(seq 30); do
  if curl -fs -H "Authorization: Bearer $token" "http://127.0.0.1:8000/alerts?limit=200" \
    | python3 -c 'import json,sys; sys.exit(not any(a["attack_type"]=="PortScan" and a["severity"]=="high" for a in json.load(sys.stdin)["items"]))'; then
    found=1; break
  fi
  sleep 2
done
[ "${found:-}" = 1 ] || fail "no High PortScan alert within 60 s"

curl -fsI http://localhost:3000/ | grep -qi '^content-security-policy:' || fail "dashboard served without a CSP"
echo "e2e: PASS (High PortScan alert over the API; dashboard CSP present)"

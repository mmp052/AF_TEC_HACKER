#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
docker compose down -v 2>/dev/null || true
docker compose pull --quiet || true
docker compose up -d
for i in $(seq 1 30); do
  if curl -fsS http://localhost:3000/ >/dev/null 2>&1; then
    echo "[ok] Juice Shop em http://localhost:3000"
    exit 0
  fi
  sleep 1
done
echo "[erro] Juice Shop nao respondeu em 30s" >&2
docker compose logs --tail 50 || true
exit 1

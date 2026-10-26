#!/usr/bin/env bash
# Starts everything without the root npm/concurrently layer:
#   demo site :3000  ->  WAF proxy :8080 + dashboard API :4000  ->  React UI :5173
# Ctrl+C stops all three.
set -e
cd "$(dirname "$0")"

[ -f backend/.env ] || { cp backend/.env.example backend/.env; echo "Created backend/.env — set JWT_SECRET before real use."; }
[ -d backend/node_modules ]  || (cd backend  && npm install)
[ -d frontend/node_modules ] || (cd frontend && npm install)

PIDS=()
cleanup() { echo; echo "Stopping..."; kill "${PIDS[@]}" 2>/dev/null || true; wait 2>/dev/null || true; exit 0; }
trap cleanup INT TERM

(cd backend && npm run target) & PIDS+=($!)
(cd backend && npm run dev)    & PIDS+=($!)
(cd frontend && npm run dev)   & PIDS+=($!)
wait

#!/usr/bin/env bash
# Starts backend + frontend together without needing the root
# npm/concurrently setup. Ctrl+C stops both.
#
# Usage:
#   ./run.sh
#
# First-time setup (once):
#   cd backend && npm install && cp .env.example .env && cd ..
#   cd frontend && npm install && cd ..

set -e

cleanup() {
  echo ""
  echo "Stopping..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
  wait "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
  exit 0
}
trap cleanup INT TERM

if [ ! -f backend/.env ]; then
  echo "backend/.env not found — copying from .env.example."
  cp backend/.env.example backend/.env
  echo "Edit backend/.env (at least JWT_SECRET) before relying on this in production."
fi

echo "Starting backend  -> http://localhost:4000"
(cd backend && npm run dev) &
BACKEND_PID=$!

echo "Starting frontend -> http://localhost:5173"
(cd frontend && npm run dev) &
FRONTEND_PID=$!

wait "$BACKEND_PID" "$FRONTEND_PID"

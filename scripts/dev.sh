#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PIDS=()

kill_pid_tree() {
  local pid="$1"
  if ! kill -0 "$pid" 2>/dev/null; then
    return
  fi
  kill "$pid" 2>/dev/null || true
  pkill -P "$pid" 2>/dev/null || true
}

cleanup() {
  echo ""
  echo "Encerrando processos de desenvolvimento..."
  for pid in "${PIDS[@]}"; do
    kill_pid_tree "$pid"
  done
  wait 2>/dev/null || true
}

trap cleanup EXIT INT TERM

echo "Iniciando backend (port 8080)..."
go run . serve &
PIDS+=($!)

sleep 2

echo "Iniciando frontend (port 5173)..."
(cd frontend && npm run dev) &
PIDS+=($!)

wait || true

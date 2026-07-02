#!/usr/bin/env bash
set -euo pipefail

kill_port() {
  local port="$1"
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" 2>/dev/null || true
    return
  fi
  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(lsof -ti :"${port}" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      kill $pids 2>/dev/null || true
    fi
  fi
}

echo "Encerrando processos nas portas 8080 e 5173..."
kill_port 8080
kill_port 5173
echo "Pronto."

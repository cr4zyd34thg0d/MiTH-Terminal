#!/usr/bin/env bash
# MiTH Terminal — Supervised background tmux daemon runner
# Author: MiTH | License: MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || command -v python || true)}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8790}"
LOG_FILE="${LOG_FILE:-${TMPDIR:-/tmp}/mith_terminal_daemon.log}"

if [[ -z "${PYTHON_BIN}" ]]; then
    echo "Error: Python 3.10+ was not found in PATH (set PYTHON_BIN or install python3)." >&2
    exit 1
fi

if ! command -v tmux >/dev/null 2>&1; then
    echo "Error: tmux is required for background supervision (or run ./start.sh directly)." >&2
    exit 1
fi

tmux kill-session -t mith_terminal_daemon 2>/dev/null || true
sleep 0.5

printf -v ESC_PY '%q' "${PYTHON_BIN}"
printf -v ESC_SERVER '%q' "${SCRIPT_DIR}/daemon/server.py"
printf -v ESC_HOST '%q' "${HOST}"
printf -v ESC_PORT '%q' "${PORT}"
printf -v ESC_LOG '%q' "${LOG_FILE}"

tmux new-session -d -s mith_terminal_daemon \
  "bash -lc 'export PYTHONUTF8=1 PYTHONIOENCODING=utf-8; while true; do ${ESC_PY} ${ESC_SERVER} --host ${ESC_HOST} --port ${ESC_PORT} >> ${ESC_LOG} 2>&1 || true; printf \"[%s] mith_terminal_daemon exited — respawning in 1s...\n\" \"\$(date -Iseconds)\" >> ${ESC_LOG}; sleep 1; done'"

for _ in $(seq 1 15); do
    if curl -fsS "http://127.0.0.1:${PORT}/api/ping" >/dev/null 2>&1; then
        break
    fi
    sleep 0.4
done

echo "MITH_TERMINAL_HEALTH=$(curl -s "http://127.0.0.1:${PORT}/api/ping")"

#!/usr/bin/env bash
# MiTH Terminal — Cross-platform 1-command launcher (macOS / Linux / WSL)
# Author: MiTH | License: MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_python310() {
    local candidate
    for candidate in ${PYTHON_BIN:+"$PYTHON_BIN"} python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
                command -v "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

if ! PYTHON_CMD="$(find_python310)"; then
    echo "MiTH Terminal requires Python 3.10 or newer — install it via brew/apt or https://www.python.org/downloads/ and re-run ./start.sh." >&2
    exit 1
fi

export PYTHONUTF8="${PYTHONUTF8:-1}"
export PYTHONIOENCODING="${PYTHONIOENCODING:-utf-8}"

exec "$PYTHON_CMD" "$SCRIPT_DIR/daemon/server.py" "$@"

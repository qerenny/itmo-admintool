#!/usr/bin/env bash
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADMINTOOL_LOG_DIR="${ADMINTOOL_LOG_DIR:-$ROOT/logs}"
export ADMINTOOL_CONFIG="${ADMINTOOL_CONFIG:-$ROOT/conf/thresholds.json}"
mkdir -p -- "$ADMINTOOL_LOG_DIR"
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1

error() {
    printf '%s | %s\n' "$(date '+%F %T')" "$*" | tee -a "$ADMINTOOL_LOG_DIR/admintool.err" >&2
    return 3
}

require() {
    local program
    for program in "$@"; do
        if ! command -v "$program" >/dev/null; then
            error "Missing dependency: $program"
            return 3
        fi
    done
}

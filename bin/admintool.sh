#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/lib/common.sh"

usage() {
    echo 'Usage: admintool.sh --health|--logs|--audit|--respond|--report|--all [--format html|json] [--dry-run]'
}

steps=()
format=json
response=()
while (( $# )); do
    case "$1" in
        --health|--logs|--audit|--respond|--report) steps+=("${1#--}") ;;
        --all) steps+=(health logs audit respond report) ;;
        --dry-run) response=(--dry-run) ;;
        --format)
            shift
            if [[ "${1:-}" != html && "${1:-}" != json ]]; then usage >&2; exit 3; fi
            format="$1"
            ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 3 ;;
    esac
    shift
done
if (( ${#steps[@]} == 0 )); then usage >&2; exit 3; fi
require python3 jq ping ss flock
if ! command -v firewall-cmd >/dev/null; then error 'Missing dependency: firewall-cmd'; exit 3; fi

exec 8>"$ADMINTOOL_LOG_DIR/admintool.lock"
flock -x 8
export ADMINTOOL_CPU_CRIT=0
ADMINTOOL_HEALTH_SUMMARY="$(mktemp "$ADMINTOOL_LOG_DIR/.health.XXXXXXXX")"
export ADMINTOOL_HEALTH_SUMMARY
trap 'rm -f -- "$ADMINTOOL_HEALTH_SUMMARY"' EXIT
overall=0

step() {
    local name="$1" rc=0 started finished
    shift
    started="$(date +%s%N)"
    "$@" || rc=$?
    finished="$(date +%s%N)"
    printf '%s | %s | rc=%d | %d ms\n' "$(date '+%F %T')" "$name" "$rc" \
        "$(( (finished-started)/1000000 ))" | tee -a "$ADMINTOOL_LOG_DIR/admintool.log"
    case "$name:$rc" in
        *:0) ;;
        health:1|logs:1|health:2|audit:2)
            if (( rc > overall )); then overall="$rc"; fi
            ;;
        *) error "Step $name failed with code $rc"; exit 3 ;;
    esac
}

for name in "${steps[@]}"; do
    case "$name" in
        health)
            step health bash "$ROOT/bin/health.sh"
            ADMINTOOL_CPU_CRIT=0
            if grep -q ' | cpu=CRIT(' "$ADMINTOOL_HEALTH_SUMMARY"; then ADMINTOOL_CPU_CRIT=1; fi
            ;;
        logs) step logs python3 "$ROOT/py/logwatch.py" --source journal ;;
        audit) step audit python3 "$ROOT/py/secaudit.py" ;;
        respond)
            if (( ${#response[@]} )); then
                step respond bash "$ROOT/bin/respond.sh" "${response[@]}"
            else
                step respond bash "$ROOT/bin/respond.sh"
            fi
            ;;
        report) step report python3 "$ROOT/py/report.py" --format "$format" ;;
    esac
done
exit "$overall"

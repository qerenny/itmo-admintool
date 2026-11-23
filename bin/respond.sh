#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/lib/common.sh"
require jq python3 flock
zone="$(jq -er '.firewall_zone' "$ADMINTOOL_CONFIG")"
timeout="$(jq -er '.firewall_timeout' "$ADMINTOOL_CONFIG")"
ledger="$ADMINTOOL_LOG_DIR/firewall-owned.tsv"
exec 9>"$ADMINTOOL_LOG_DIR/firewall.lock"
flock -x 9

action() {
    printf '%s | %s\n' "$(date '+%F %T')" "$*" | tee -a "$ADMINTOOL_LOG_DIR/actions.log"
}

valid_ipv4() {
    python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$1" 2>/dev/null
}

rule_for() {
    printf 'rule family="ipv4" source address="%s" reject' "$1"
}

query() {
    local result=0
    firewall-cmd --zone="$1" --query-rich-rule="$2" >/dev/null || result=$?
    case "$result" in
        0|1) return "$result" ;;
        *) error "firewalld query failed ($result)"; exit 3 ;;
    esac
}

mode="${1:-}"
if [[ "$mode" == --unblock-all ]]; then
    require firewall-cmd
    [[ -f "$ledger" ]] || exit 0
    while IFS=$'\t' read -r owned_zone ip; do
        valid_ipv4 "$ip" || continue
        rule="$(rule_for "$ip")"
        if query "$owned_zone" "$rule"; then
            firewall-cmd --zone="$owned_zone" --remove-rich-rule="$rule" || exit 3
            action "OK unblocked $ip in $owned_zone"
        fi
    done < "$ledger"
    : > "$ledger"
    exit 0
fi
if [[ -n "$mode" && "$mode" != --dry-run ]]; then
    error "Unknown response mode: $mode"
    exit 3
fi

journal="$ADMINTOOL_LOG_DIR/logwatch.json"
audit="$ADMINTOOL_LOG_DIR/secaudit.json"
if [[ -f "$journal" ]]; then
    ips="$(python3 "$ROOT/py/response_input.py" "$journal")" || exit 3
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        if ! valid_ipv4 "$ip"; then
            action 'WARN ignored non-IPv4 failed-login source'
            continue
        fi
        if jq -e --arg ip "$ip" '.protected_ips | index($ip) != null' "$ADMINTOOL_CONFIG" >/dev/null; then
            action "WARN protected address $ip exceeded the failed-login threshold"
            continue
        fi
        if [[ "$mode" == --dry-run ]]; then
            action "WARN dry run: would reject $ip for $timeout due to failed SSH logins"
            continue
        fi
        require firewall-cmd
        rule="$(rule_for "$ip")"
        if ! query "$zone" "$rule"; then
            firewall-cmd --zone="$zone" --add-rich-rule="$rule" --timeout="$timeout" || exit 3
            printf '%s\t%s\n' "$zone" "$ip" >> "$ledger"
            action "WARN rejected $ip for $timeout due to failed SSH logins"
        fi
    done <<< "$ips"
fi
if [[ -f "$audit" ]]; then
    count="$(jq -er '.unexpected_ports | length' "$audit")" || exit 3
    if (( count > 0 )); then
        action "WARN $count unexpected sockets: review the listening services"
    fi
fi
if [[ "${ADMINTOOL_CPU_CRIT:-0}" == 1 ]]; then
    snapshot="$ADMINTOOL_LOG_DIR/processes_$(date '+%F_%H-%M-%S').json"
    python3 "$ROOT/py/report.py" --top-processes --out "$snapshot" || exit 3
    action "CRIT CPU: recorded top processes in $(basename -- "$snapshot")"
fi

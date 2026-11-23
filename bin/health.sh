#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/lib/common.sh"
require jq ping df free awk
if ! jq -e '[.cpu, .mem, .disk, .loss] | all(type == "number" and floor == . and . >= 0 and . <= 100)' "$ADMINTOOL_CONFIG" >/dev/null; then
    error 'Invalid health thresholds'
    exit 3
fi
read -r cpu_limit mem_limit disk_limit loss_limit < <(
    jq -r '[.cpu, .mem, .disk, .loss] | @tsv' "$ADMINTOOL_CONFIG"
)
if ! host="$(jq -er '.ping_host | strings | select(length > 0)' "$ADMINTOOL_CONFIG")"; then
    error 'Invalid ping host'
    exit 3
fi

classify() {
    local value="$1" limit="$2"
    if (( value >= limit + 10 || value == 100 )); then
        status=CRIT
        return 2
    elif (( value >= limit )); then
        status=WARN
        return 1
    fi
    status=OK
}

cpu_ticks() {
    awk '/^cpu / { print $2+$3+$4+$5+$6+$7+$8+$9, $5+$6; exit }' /proc/stat
}

check_cpu() {
    local first idle_first last idle_last
    read -r first idle_first < <(cpu_ticks) || return 3
    sleep 1
    read -r last idle_last < <(cpu_ticks) || return 3
    (( last > first )) || return 3
    value=$((100 * ((last-first) - (idle_last-idle_first)) / (last-first)))
    classify "$value" "$cpu_limit"
}

check_mem() {
    # Older free reports buffers and cache in separate columns.
    value="$(free -m | awk '
        NR==1 { legacy=($5=="buffers" && $6=="cached") }
        /^Mem:/ && $2 > 0 {
            used=$3
            if (legacy) used-=$6+$7
            print int(100*used/$2)
        }
    ')" || return 3
    [[ "$value" =~ ^[0-9]+$ ]] || return 3
    classify "$value" "$mem_limit"
}

check_disk() {
    value="$(df -P / /var /home | awk 'NR>1 {sub(/%/,"",$5); if($5+0>max) max=$5+0} END {print max+0}')" || return 3
    classify "$value" "$disk_limit"
}

check_net() {
    local output rc=0
    output="$(ping -c 5 -W 2 -- "$host" 2>&1)" || rc=$?
    if (( rc > 1 )); then
        return 3
    fi
    value="$(awk -F', ' '/packet loss/ {for(i=1;i<=NF;i++) if($i ~ /packet loss/) {split($i,a,"%"); print int(a[1])}}' <<< "$output")"
    [[ "$value" =~ ^[0-9]+$ ]] || return 3
    classify "$value" "$loss_limit"
}

maximum=0
summary="$(date '+%F %T')"
for metric in cpu mem disk net; do
    rc=0
    "check_$metric" || rc=$?
    if (( rc >= 3 )); then
        error "Health probe failed: $metric"
        exit 3
    fi
    if (( rc > maximum )); then maximum=$rc; fi
    summary+=" | $metric=$status($value%)"
done
read -r load _ < /proc/loadavg
printf '%s\n' "$summary" | tee -a "$ADMINTOOL_LOG_DIR/health_$(date '+%F_%H-%M').log"
if [[ -n "${ADMINTOOL_HEALTH_SUMMARY:-}" ]]; then
    printf '%s\n' "$summary" > "$ADMINTOOL_HEALTH_SUMMARY"
fi
printf 'Load average (1m): %s\n' "$load"
exit "$maximum"

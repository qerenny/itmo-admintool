"""Group errors and count failed SSH events in a bounded time window."""
import argparse
import ipaddress
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from common import LOGS, configuration, period, write_json

RECORD = re.compile(
    r"^(?P<stamp>\d{4}-\d\d-\d\dT\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)"
    r"\s+(?P<host>\S+)\s+(?P<unit>[^:\s\[]+)(?:\[\d+\])?:\s*(?P<text>.*)$"
)
LEVEL = re.compile(r"^(?:\[(debug|info|notice|warn(?:ing)?|err(?:or)?|crit|alert|emerg)\]"
                   r"|(debug|info|notice|warn(?:ing)?|err(?:or)?|crit|alert|emerg):)\s*", re.I)
ERROR = re.compile(r"error|fail|denied|crit|panic", re.I)
LOGIN = re.compile(r"^(?:Failed password for|Invalid user)\b.*?\bfrom\s+(\S+)", re.I)
ADDRESS = re.compile(r"(?<![\w.])(?:\d{1,3}(?:\.\d{1,3}){3}|[a-f0-9:]*:[a-f0-9:]+)(?!\w|\.\w)", re.I)
PATH = re.compile(r"(?<![\w/])/(?:[\w.+@%~-]+/)*[\w.+@%~-]+")


def parse(line, now):
    match = RECORD.match(line.rstrip("\r\n"))
    if not match:
        return None
    data = match.groupdict()
    try:
        stamp = data["stamp"]
        if "T" in stamp:
            time = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone()
        else:
            time = datetime.strptime(stamp, "%b %d %H:%M:%S")
            time = time.replace(year=now.year).astimezone()
            if time > now:
                time = time.replace(year=now.year - 1)
    except ValueError:
        return None
    level = LEVEL.match(data["text"])
    data["level"] = (level[1] or level[2]).lower() if level else None
    data["time"] = time
    return data


def address(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def normalize(message):
    message = PATH.sub("PATH", message)
    message = ADDRESS.sub(lambda match: "IP" if address(match[0]) else match[0], message)
    return re.sub(r"\d+", "N", message)


def analyze(lines, start, end, top, threshold):
    counts = {"total": 0, "matched_errors": 0, "unparsed": 0}
    errors, ips = Counter(), Counter()
    examples = {}
    for line in lines:
        counts["total"] += 1
        entry = parse(line, end)
        if entry is None:
            counts["unparsed"] += 1
            continue
        if not start <= entry["time"] <= end:
            continue
        message = entry["text"]
        if ERROR.search(message):
            pattern = normalize(message)
            counts["matched_errors"] += 1
            errors[pattern] += 1
            examples.setdefault(pattern, message)
        login = LOGIN.match(message) if entry["unit"].startswith("sshd") else None
        ip = address(login[1]) if login else None
        if ip:
            ips[ip] += 1
    return {
        "period": {"from": start.isoformat(), "to": end.isoformat()},
        "counts": counts,
        "top_errors": [
            {"pattern": key, "count": n, "example": examples[key]}
            for key, n in errors.most_common(top)
        ],
        "top_failed_ips": [{"ip": ip, "count": n} for ip, n in ips.most_common(5)],
        "over_threshold_ips": [{"ip": ip, "count": n}
                               for ip, n in ips.most_common() if n > threshold],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="24h")
    parser.add_argument("--top", type=int, default=5)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--log", type=Path)
    source.add_argument("--source", choices=["journal"])
    parser.add_argument("--out", type=Path, default=LOGS / "logwatch.json")
    args = parser.parse_args()
    if args.top < 1:
        parser.error("--top must be positive")
    try:
        start, end = period(args.since)
        threshold = configuration()["failed_logins"]
        if args.source == "journal":
            stamp = start.strftime("%Y-%m-%d %H:%M:%S")
            result = subprocess.run(
                ["journalctl", "--since", stamp, "-o", "short-iso", "--no-pager", "--quiet"],
                check=True, capture_output=True, text=True, errors="replace"
            )
            data = analyze(result.stdout.splitlines(), start, end, args.top, threshold)
        else:
            with (args.log or Path("/var/log/messages")).open(errors="replace", encoding="utf-8") as stream:
                data = analyze(stream, start, end, args.top, threshold)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"logwatch: {getattr(error, 'stderr', None) or error}", file=sys.stderr)
        return 2
    try:
        write_json(args.out, data)
    except OSError as error:
        print(f"logwatch: {error}", file=sys.stderr)
        return 3
    print("Count | Error pattern")
    for item in data["top_errors"]:
        print(f"{item['count']:5} | {item['pattern']}")
    print("Count | Failed-login IP")
    for item in data["top_failed_ips"]:
        print(f"{item['count']:5} | {item['ip']}")
    print(data["counts"])
    return int(bool(data["over_threshold_ips"]))


if __name__ == "__main__":
    sys.exit(main())

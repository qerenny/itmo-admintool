"""Aggregate monitoring records or print a live CPU process snapshot."""
import argparse
import html
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from common import LOGS, period, write_json, write_text

SECTIONS = (
    ("health", "Здоровье системы"),
    ("journal", "Топ ошибок"),
    ("audit", "Подозрительные учётки и файлы"),
    ("actions", "Действия реагирования"),
)


def timed_lines(path, start, end):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            stamp, value = line.split(" | ", 1)
            time = datetime.fromisoformat(stamp).astimezone()
        except ValueError:
            continue
        if start <= time <= end:
            rows.append({"time": stamp, "message": value})
    return rows


def snapshot(name, field, start, end):
    path = LOGS / name
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    stamp = data["period"]["to"] if field == "period" else data[field]
    time = datetime.fromisoformat(stamp).astimezone()
    return data if start <= time <= end else None


def collect(start, end):
    health = [row for path in sorted(LOGS.glob("health_*.log"))
              for row in timed_lines(path, start, end)]
    journal = snapshot("logwatch.json", "period", start, end)
    audit = snapshot("secaudit.json", "generated_at", start, end)
    actions = timed_lines(LOGS / "actions.log", start, end)
    counts = Counter({key: 0 for key in ("OK", "WARN", "CRIT")})
    for row in health:
        for item in row["message"].split(" | "):
            _, _, status = item.partition("=")
            status = status.split("(")[0]
            if status in counts:
                counts[status] += 1
    if journal:
        counts["WARN" if journal["over_threshold_ips"] else "OK"] += 1
    if audit:
        counts[audit["status"]] += 1
    for action in actions:
        level = action["message"].split(" ", 1)[0]
        if level in counts:
            counts[level] += 1
    return {"period": {"from": start.isoformat(), "to": end.isoformat()},
            "counts": dict(counts), "health": health, "journal": journal,
            "audit": audit, "actions": actions}


def table(headers, rows):
    head = "".join(f"<th>{html.escape(title)}</th>" for title in headers)
    body = "".join("<tr>" + "".join(
        f"<td>{html.escape(str(value))}</td>" for value in row
    ) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(data):
    counts = table(("Статус", "Количество"), data["counts"].items())
    blocks = {"health": table(("Время", "Показатели"),
                              ((r["time"], r["message"]) for r in data["health"])),
              "actions": table(("Время", "Действие"),
                               ((r["time"], r["message"]) for r in data["actions"]))}
    journal = data["journal"] or {}
    blocks["journal"] = table(("Шаблон", "Количество", "Пример"),
                              ((r["pattern"], r["count"], r["example"])
                               for r in journal.get("top_errors", [])))
    blocks["journal"] += table(("IP неудачного входа", "Количество"),
                               ((r["ip"], r["count"]) for r in journal.get("top_failed_ips", [])))
    audit = data["audit"] or {}
    categories = {"uid0": "UID 0", "empty_passwords": "Пустой пароль",
                  "suid_suspicious": "SUID/SGID вне списка", "world_writable": "Права 777/666",
                  "orphan": "Неизвестный UID", "home_executable": "Исполняемый файл в /home",
                  "unexpected_ports": "Нестандартный порт"}
    blocks["audit"] = table(("Категория", "Находка"),
                            ((label, json.dumps(row, ensure_ascii=False) if isinstance(row, dict) else row)
                             for key, label in categories.items() for row in audit.get(key, [])))
    sections = "".join(f"<section><h2>{title}</h2>{blocks[key]}</section>" for key, title in SECTIONS)
    return ("<!doctype html><html lang='ru'><meta charset='utf-8'>"
            "<title>Мониторинг РЕД ОС</title><style>"
            "body{font:16px system-ui;margin:2em;max-width:85em}"
            "table{border-collapse:collapse;margin:1em 0}th,td{border:1px solid #bbb;padding:.4em}"
            "th{background:#eee;text-align:left}td{overflow-wrap:anywhere}"
            "</style><h1>Мониторинг РЕД ОС</h1>" + counts + sections + "</html>\n")


def processes():
    output = subprocess.check_output(
        ["ps", "-eo", "pid,ppid,pcpu,pmem,comm", "--sort=-pcpu"], text=True
    )
    rows = []
    for line in output.splitlines()[1:6]:
        pid, ppid, cpu, mem, command = line.split(maxsplit=4)
        rows.append({"pid": int(pid), "ppid": int(ppid), "cpu": float(cpu),
                     "mem": float(mem), "command": command})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="7d")
    parser.add_argument("--format", choices=("json", "html"), default="json")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--top-processes", action="store_true")
    args = parser.parse_args()
    try:
        if args.top_processes:
            data = processes()
        else:
            data = collect(*period(args.since))
            if not any(data[key] for key, _ in SECTIONS):
                print("report: no data in the requested period", file=sys.stderr)
                return 2
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"report: {error}", file=sys.stderr)
        return 2
    try:
        if args.top_processes and not args.out:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        elif args.top_processes or args.format == "json":
            write_json(args.out or LOGS / "report.json", data)
        else:
            write_text(args.out or LOGS / "report.html", render_html(data))
    except OSError as error:
        print(f"report: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

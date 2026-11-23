"""Shared configuration, reporting and time-window helpers."""
import json
import os
import re
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGS = Path(os.environ.get("ADMINTOOL_LOG_DIR", ROOT / "logs"))
CONFIG = Path(os.environ.get("ADMINTOOL_CONFIG", ROOT / "conf/thresholds.json"))


def period(value):
    match = re.fullmatch(r"([1-9][0-9]{0,5})([hd])", value)
    if not match:
        raise ValueError("period must be a positive number followed by h or d")
    amount, unit = match.groups()
    end = datetime.now().astimezone()
    return end - timedelta(hours=int(amount) * (24 if unit == "d" else 1)), end


def configuration():
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temp = Path(stream.name)
            stream.write(text)
        temp.replace(path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def write_json(path, data):
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")

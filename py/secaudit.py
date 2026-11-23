"""Inventory local account, file permission and listening-port findings."""
import argparse
import os
import re
import stat
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

from common import LOGS, configuration, write_json

KNOWN_PRIVILEGED = {
    f"/usr/bin/{name}" for name in (
        "sudo", "passwd", "su", "mount", "umount", "chsh", "chfn",
        "newgrp", "gpasswd", "pkexec", "crontab",
    )
}


def parse_passwd(lines):
    accounts = []
    for line in lines:
        fields = line.rstrip("\n").split(":")
        if len(fields) == 7 and fields[2].isdigit():
            accounts.append({"name": fields[0], "uid": int(fields[2]), "shell": fields[6]})
    return accounts


def privilege_bits(mode):
    return [label for bit, label in ((stat.S_ISUID, "SUID"), (stat.S_ISGID, "SGID")) if mode & bit]


def files_under(roots, skipped):
    seen = set()

    def onerror(error):
        skipped.append(str(error))

    for root in roots:
        root = Path(root).resolve()
        if root in seen or not root.exists():
            continue
        seen.add(root)
        for base, _, names in os.walk(root, onerror=onerror, followlinks=False):
            for name in names:
                path = Path(base) / name
                try:
                    info = path.lstat()
                    if stat.S_ISREG(info.st_mode):
                        yield path, info
                except OSError as error:
                    onerror(error)


def password_expiration(name):
    result = subprocess.run(["chage", "-l", "--", name], capture_output=True, text=True,
                            errors="replace", env={**os.environ, "LC_ALL": "C"},
                            timeout=5, check=True)
    for line in result.stdout.splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "Password expires":
            value = value.strip()
            if value == "never":
                return {"expires": value, "expired": False}
            if value == "password must be changed":
                return {"expires": value, "expired": True}
            expiry = datetime.strptime(value, "%b %d, %Y").date()
            return {"expires": expiry.isoformat(), "expired": expiry < date.today()}
    return {"expires": None, "expired": None}


def audit():
    accounts = parse_passwd(Path("/etc/passwd").read_text(errors="replace").splitlines())
    skipped = []
    passwords = {}
    try:
        with open("/etc/shadow", errors="replace") as shadow:
            for line in shadow:
                fields = line.rstrip("\n").split(":")
                if len(fields) >= 2:
                    passwords[fields[0]] = not fields[1]
    except OSError as error:
        skipped.append(str(error))
    shells = {"nologin", "false"}
    nologin = [a["name"] for a in accounts if Path(a["shell"]).name in shells]
    expiration = []
    for account in accounts:
        name = account["name"]
        if name in nologin or account["shell"] not in {"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}:
            continue
        try:
            expiration.append({"user": name, **password_expiration(name)})
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            skipped.append(f"chage {name}: {error}")
            expiration.append({"user": name, "expires": None, "expired": None})
    suspicious = []
    for path, info in files_under(("/usr", "/bin", "/sbin", "/opt"), skipped):
        bits = privilege_bits(info.st_mode)
        if bits and str(path) not in KNOWN_PRIVILEGED:
            suspicious.append({"path": str(path), "bits": bits})
    world, executable, orphan = [], [], []
    known_uids = {a["uid"] for a in accounts}
    for path, info in files_under(("/etc", "/home"), skipped):
        mode = info.st_mode & 0o777
        if mode in (0o777, 0o666):
            world.append({"path": str(path), "mode": oct(mode)})
        if path.is_relative_to("/home") and mode & 0o111 == 0o111:
            executable.append(str(path))
        if info.st_uid not in known_uids:
            orphan.append({"path": str(path), "uid": info.st_uid})
    result = subprocess.run(["ss", "-H", "-tulpn"], check=True, capture_output=True,
                            text=True, errors="replace")
    expected = set(configuration()["expected_ports"])
    unexpected = []
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=6)
        if len(fields) < 6:
            continue
        match = re.search(r":(\d+)$", fields[4])
        if match and int(match[1]) not in expected:
            unexpected.append({"proto": fields[0], "endpoint": fields[4], "port": int(match[1]),
                               "process": fields[6] if len(fields) > 6 else ""})
    return {
        "generated_at": datetime.now().astimezone().isoformat(),
        "uid0": [a["name"] for a in accounts if a["uid"] == 0 and a["name"] != "root"],
        "empty_passwords": [name for name, empty in passwords.items() if empty],
        "bash_without_password": [a["name"] for a in accounts
                                  if Path(a["shell"]).name == "bash" and passwords.get(a["name"])],
        "nologin": nologin, "expiration": expiration, "suid_suspicious": suspicious,
        "world_writable": world, "home_executable": executable, "orphan": orphan,
        "unexpected_ports": unexpected, "skipped": len(skipped), "skipped_examples": skipped[:10],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=LOGS / "secaudit.json")
    args = parser.parse_args()
    try:
        data = audit()
        keys = ("uid0", "empty_passwords", "suid_suspicious", "world_writable", "orphan",
                "unexpected_ports")
        critical = any(data[key] for key in keys[:-1])
        data["status"] = "CRIT" if critical else ("WARN" if data["unexpected_ports"] else "OK")
        write_json(args.out, data)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"secaudit: {error}", file=sys.stderr)
        return 3
    print(data["status"] + ": " + ", ".join(f"{key}={len(data[key])}" for key in keys))
    if data["skipped"]:
        print(f"Skipped: {data['skipped']}. {data['skipped_examples'][0]}", file=sys.stderr)
    return 2 if critical else 0


if __name__ == "__main__":
    sys.exit(main())

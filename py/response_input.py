"""Read validated alert candidates from a recent journal analysis."""
import json
import ipaddress
import sys
from datetime import datetime, timedelta
from pathlib import Path

from common import configuration


def main(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        end = datetime.fromisoformat(data["period"]["to"])
        if not timedelta(0) <= datetime.now().astimezone() - end <= timedelta(minutes=15):
            print("respond: logwatch result is older than 15 minutes or dated in the future",
                  file=sys.stderr)
            return 0
        threshold = configuration()["failed_logins"]
        for row in data.get("over_threshold_ips", data["top_failed_ips"]):
            if row["count"] > threshold:
                try:
                    print(ipaddress.ip_address(row["ip"]))
                except ValueError:
                    print("respond: ignored malformed IP", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"respond: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

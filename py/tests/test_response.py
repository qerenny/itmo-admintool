import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from common import ROOT


@unittest.skipUnless(shutil.which("jq"), "requires jq")
class ResponseTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        self.add_command("flock", "exit 0")
        self.add_command("python3", f'exec "{sys.executable}" "$@"')
        self.add_command("firewall-cmd", """
case "$2" in
    --query-rich-rule=*) test -e "$ADMINTOOL_LOG_DIR/mock-rule" ;;
    --add-rich-rule=*) touch "$ADMINTOOL_LOG_DIR/mock-rule"
        printf '%s\\n' add >> "$ADMINTOOL_LOG_DIR/mock-calls" ;;
    --remove-rich-rule=*) rm "$ADMINTOOL_LOG_DIR/mock-rule"
        printf '%s\\n' remove >> "$ADMINTOOL_LOG_DIR/mock-calls" ;;
    *) exit 9 ;;
esac
""")
        self.env = {**os.environ, "ADMINTOOL_LOG_DIR": str(self.path),
                    "ADMINTOOL_CONFIG": str(ROOT / "conf/thresholds.json"),
                    "PATH": f"{self.path}:{os.environ['PATH']}"}

    def add_command(self, name, script):
        path = self.path / name
        path.write_text("#!/bin/bash\n" + script + "\n")
        path.chmod(0o755)

    def set_alert(self, stamp):
        payload = {"period": {"to": stamp.isoformat()}, "top_failed_ips": [
            {"ip": "192.0.2.5", "count": 11},
            {"ip": "127.0.0.1", "count": 11},
            {"ip": "192.0.2.6\n192.0.2.7", "count": 11},
        ]}
        (self.path / "logwatch.json").write_text(json.dumps(payload))

    def respond(self, *arguments):
        return subprocess.run(["bash", str(ROOT / "bin/respond.sh"), *arguments],
                              env=self.env, check=True, capture_output=True, text=True)

    def test_dry_run_idempotence_and_rollback(self):
        self.set_alert(datetime.now().astimezone())
        self.assertIn("would reject 192.0.2.5", self.respond("--dry-run").stdout)
        calls = self.path / "mock-calls"
        self.assertFalse(calls.exists())
        self.respond()
        self.respond()
        self.respond("--unblock-all")
        self.assertEqual(calls.read_text().splitlines(), ["add", "remove"])

    def test_stale_analysis(self):
        self.set_alert(datetime.now().astimezone() - timedelta(hours=1))
        self.assertIn("older than 15 minutes", self.respond().stderr)
        self.assertFalse((self.path / "mock-calls").exists())

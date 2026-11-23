import tempfile
import stat
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import logwatch
import report
import secaudit


class LogwatchTest(unittest.TestCase):
    def setUp(self):
        fixture = Path(__file__).with_name("fixtures") / "sample.log"
        start = datetime.fromisoformat("2026-02-10T00:00:00+00:00")
        end = datetime.fromisoformat("2026-02-11T00:00:00+00:00")
        self.data = logwatch.analyze(fixture.read_text().splitlines(), start, end, 5, 1)

    def test_top_errors(self):
        self.assertEqual(self.data["counts"]["matched_errors"], 4)
        self.assertIn("[error] denied PATH at IP",
                      [entry["pattern"] for entry in self.data["top_errors"]])
        self.assertEqual([r["count"] for r in self.data["top_errors"]], [2, 2])

    def test_top_ips(self):
        expected = {"ip": "192.0.2.5", "count": 2}
        self.assertEqual(self.data["top_failed_ips"][0], expected)
        self.assertEqual(self.data["over_threshold_ips"], [expected])

    def test_unparsed(self):
        self.assertEqual(self.data["counts"]["unparsed"], 1)
        self.assertEqual(self.data["counts"]["total"], 6)


class AuditTest(unittest.TestCase):
    def test_uid0(self):
        data = secaudit.parse_passwd([
            "root:x:0:0:root:/root:/bin/bash",
            "other:x:0:0::/home/other:/bin/bash",
            "bad",
        ])
        self.assertEqual([r["name"] for r in data if r["uid"] == 0], ["root", "other"])

    def test_suid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "program"
            path.touch()
            path.chmod(0o4755)
            mode = path.stat().st_mode
            if sys.platform == "darwin" and not mode & stat.S_ISUID:
                self.skipTest("this macOS workspace clears SUID; verify chmod on the Linux VM")
            self.assertEqual(secaudit.privilege_bits(mode), ["SUID"])

    def test_suid_mode_bits(self):
        self.assertEqual(secaudit.privilege_bits(stat.S_IFREG | 0o4755), ["SUID"])


class ReportTest(unittest.TestCase):
    def test_html_uses_json_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "health_example.log").write_text(
                "2026-02-10 10:00:00 | cpu=OK(5%) | mem=WARN(90%) | net=CRIT(100%)\n"
            )
            start = datetime(2026, 2, 10).astimezone()
            end = datetime(2026, 2, 11).astimezone()
            with patch.object(report, "LOGS", path):
                data = report.collect(start, end)
        output = report.render_html(data)
        self.assertEqual(data["counts"], {"OK": 1, "WARN": 1, "CRIT": 1})
        for _, title in report.SECTIONS:
            self.assertIn(f"<h2>{title}</h2>", output)
        for status, count in data["counts"].items():
            self.assertIn(f"<td>{status}</td><td>{count}</td>", output)

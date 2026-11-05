import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from login_guard import analyse, read_events


ROOT = Path(__file__).resolve().parents[1]


class LoginGuardTests(unittest.TestCase):
    def parse(self, rows):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.csv"
            path.write_text("timestamp,username,source_ip,status\n" + rows, encoding="utf-8")
            return read_events(path)

    def test_sample_has_one_alert_and_correct_totals(self):
        report = analyse(*read_events(ROOT / "samples/login_events.csv"))
        self.assertEqual(report["summary"], {"valid_events": 12, "successful_logins": 4,
                         "failed_logins": 8, "unique_ips": 4, "unique_users": 4, "invalid_rows": 0})
        self.assertEqual(len(report["alerts"]), 1)
        self.assertEqual(report["alerts"][0]["source_ip"], "203.0.113.10")
        self.assertEqual(report["alerts"][0]["failed_attempts"], 5)

    def test_exact_boundary_included_and_old_event_expires(self):
        events, errors = self.parse("2026-11-01T00:00:00Z,a,192.0.2.1,failure\n"
                                  "2026-11-01T00:05:00Z,a,192.0.2.1,failure\n"
                                  "2026-11-01T00:10:01Z,a,192.0.2.1,failure\n")
        report = analyse(events, errors, threshold=2)
        self.assertEqual(report["alerts"][0]["failed_attempts"], 2)
        self.assertEqual(analyse(events, errors, threshold=3)["alerts"], [])

    def test_offsets_unordered_rows_and_midnight(self):
        events, errors = self.parse("2026-11-02T08:01:00+08:00,b,192.0.2.1,failure\n"
                                  "2026-11-01T23:59:00Z,a,192.0.2.1,failure\n")
        alert = analyse(events, errors, threshold=2)["alerts"][0]
        self.assertEqual(alert["usernames"], ["a", "b"])
        self.assertEqual(alert["window_end"], "2026-11-02T00:01:00+00:00")

    def test_success_does_not_reset_failure_window(self):
        events, errors = self.parse("2026-11-01T00:00:00Z,a,192.0.2.1,failure\n"
                                  "2026-11-01T00:01:00Z,a,192.0.2.1,success\n"
                                  "2026-11-01T00:02:00Z,a,192.0.2.1,failure\n")
        self.assertEqual(analyse(events, errors, threshold=2)["alerts"][0]["failed_attempts"], 2)

    def test_separate_ips_not_combined(self):
        events, errors = self.parse("2026-11-01T00:00:00Z,a,192.0.2.1,failure\n"
                                  "2026-11-01T00:00:00Z,a,192.0.2.2,failure\n")
        self.assertEqual(analyse(events, errors, threshold=2)["alerts"], [])

    def test_invalid_rows_skipped_and_ipv6_normalized(self):
        events, errors = self.parse("2026-11-01T00:00:00Z,a,2001:db8::1,failure\n"
                                  "2026-11-01T00:01:00Z,a,2001:0db8:0:0:0:0:0:1,failure\n"
                                  "2026-11-01T00:02:00,a,192.0.2.1,failure\n"
                                  "bad,a,192.0.2.1,failure\n"
                                  "2026-11-01T00:02:00Z,a,invalid-ip,failure\n"
                                  "2026-11-01T00:02:00Z,a,192.0.2.1,unknown\n"
                                  "2026-11-01T00:02:00Z,,192.0.2.1,failure\n"
                                  "2026-11-01T00:02:00Z,a,192.0.2.1\n"
                                  "2026-11-01T00:02:00Z,a,192.0.2.1,failure,extra\n")
        report = analyse(events, errors, threshold=2)
        self.assertEqual(report["summary"]["invalid_rows"], 7)
        self.assertEqual(report["summary"]["valid_events"], 2)
        self.assertEqual(report["alerts"][0]["failed_attempts"], 2)

    def test_peak_window_recorded_once_per_ip(self):
        events, errors = self.parse("".join(f"2026-11-01T00:0{i}:00Z,a,192.0.2.1,failure\n" for i in range(4)))
        report = analyse(events, errors, threshold=2)
        self.assertEqual(len(report["alerts"]), 1)
        self.assertEqual(report["alerts"][0]["failed_attempts"], 4)

    def test_empty_data_is_valid_but_bad_headers_rejected(self):
        self.assertEqual(analyse(*self.parse(""))["summary"]["valid_events"], 0)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.csv"
            for contents in ("", "time,user,ip,status\n", "timestamp,username,source_ip,status,status\n"):
                path.write_text(contents, encoding="utf-8")
                with self.assertRaises(ValueError):
                    read_events(path)

    def test_json_cli_and_error_exit(self):
        result = subprocess.run([sys.executable, str(ROOT / "login_guard.py"),
                                 str(ROOT / "samples/login_events.csv"), "--json"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["alerts"][0]["failed_attempts"], 5)
        for arguments in ([str(ROOT / "samples/login_events.csv"), "--threshold", "1"],
                          [str(ROOT / "samples/login_events.csv"), "--window-minutes", "0"],
                          [str(ROOT / "samples/login_events.csv"), "--window-minutes", "10081"],
                          [str(ROOT / "samples/does-not-exist.csv")]):
            result = subprocess.run([sys.executable, str(ROOT / "login_guard.py"), *arguments], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertTrue(result.stderr.startswith("Error:"))


if __name__ == "__main__":
    unittest.main()

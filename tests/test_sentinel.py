import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sentinel  # noqa: E402

YEAR = 2026


def failed(ip, sec, user="root", invalid=False):
    t = datetime(YEAR, 10, 20, 12, 0, 0) + timedelta(seconds=sec)
    return sentinel.Event(t, "failed", user, ip, invalid)


def accepted(ip, sec, user="root"):
    t = datetime(YEAR, 10, 20, 12, 0, 0) + timedelta(seconds=sec)
    return sentinel.Event(t, "accepted", user, ip)


class ParsingTests(unittest.TestCase):
    def test_failed_password(self):
        line = "Oct 20 02:14:02 web01 sshd[4101]: Failed password for root from 203.0.113.45 port 40001 ssh2"
        ev = sentinel.parse_line(line, YEAR)
        self.assertEqual((ev.kind, ev.user, ev.ip, ev.invalid_user), ("failed", "root", "203.0.113.45", False))

    def test_invalid_user_flag(self):
        line = "Oct  5 02:14:02 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.45 port 1 ssh2"
        ev = sentinel.parse_line(line, YEAR)
        self.assertTrue(ev.invalid_user)
        self.assertEqual(ev.user, "admin")

    def test_accepted(self):
        line = "Oct 20 09:05:51 web01 sshd[6007]: Accepted publickey for alice from 192.0.2.10 port 60219 ssh2: RSA SHA256:abc"
        ev = sentinel.parse_line(line, YEAR)
        self.assertEqual((ev.kind, ev.user), ("accepted", "alice"))

    def test_irrelevant_lines_ignored(self):
        self.assertIsNone(sentinel.parse_line("Oct 20 01:00:05 web01 sshd[800]: Server listening on 0.0.0.0 port 22.", YEAR))
        self.assertIsNone(sentinel.parse_line("garbage", YEAR))

    def test_impossible_date_ignored(self):
        line = "Feb 29 01:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"
        self.assertIsNone(sentinel.parse_line(line, 2026))  # 2026 is not a leap year


class DetectionTests(unittest.TestCase):
    def test_peak_in_window(self):
        times = [datetime(YEAR, 1, 1, 0, 0, s) for s in (0, 1, 2, 30, 31)]
        self.assertEqual(sentinel.peak_in_window(times, 5), 3)
        self.assertEqual(sentinel.peak_in_window(times, 60), 5)

    def test_burst_is_flagged(self):
        events = [failed("203.0.113.1", i) for i in range(6)]
        alerts = sentinel.analyze(events, threshold=5, window=60)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "MEDIUM")

    def test_slow_attempts_not_flagged(self):
        events = [failed("203.0.113.2", i * 120) for i in range(10)]
        self.assertEqual(sentinel.analyze(events, threshold=5, window=60), [])

    def test_high_severity_for_huge_burst(self):
        events = [failed("203.0.113.3", i) for i in range(20)]
        self.assertEqual(sentinel.analyze(events, threshold=5)[0].severity, "HIGH")

    def test_success_after_failures_is_critical(self):
        events = [failed("198.51.100.9", i, "deploy") for i in range(6)] + [accepted("198.51.100.9", 30, "deploy")]
        alert = sentinel.analyze(events)[0]
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.compromised_user, "deploy")

    def test_success_before_failures_is_not_critical(self):
        events = [accepted("198.51.100.9", -100, "deploy")] + [failed("198.51.100.9", i) for i in range(6)]
        events[0] = sentinel.Event(datetime(YEAR, 10, 20, 11, 0, 0), "accepted", "deploy", "198.51.100.9")
        self.assertEqual(sentinel.analyze(events)[0].severity, "MEDIUM")

    def test_username_spraying(self):
        events = [failed("203.0.113.4", i * 300, f"user{i}", True) for i in range(6)]
        alert = sentinel.analyze(events, spray_users=5)[0]
        self.assertIn("spraying", alert.reasons[0])

    def test_typo_then_login_not_flagged(self):
        events = [failed("192.0.2.10", 0, "alice"), failed("192.0.2.10", 9, "alice"), accepted("192.0.2.10", 21, "alice")]
        self.assertEqual(sentinel.analyze(events), [])


class SafetyTests(unittest.TestCase):
    def test_csv_formula_injection_neutralised(self):
        self.assertEqual(sentinel.csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(sentinel.csv_safe("normal"), "normal")

    def test_block_suggestions_reject_non_ips(self):
        bad = sentinel.Alert("1.2.3.4;rm", "HIGH", 9, 9, "", "", [], 0)
        good = sentinel.Alert("203.0.113.5", "HIGH", 9, 9, "", "", [], 0)
        out = "\n".join(sentinel.block_suggestions([bad, good]))
        self.assertNotIn("ufw deny from 1.2.3.4;rm", out)
        self.assertIn("ufw deny from 203.0.113.5", out)


class CliTests(unittest.TestCase):
    def test_sample_log_exit_code_and_reports(self):
        sample = os.path.join(os.path.dirname(__file__), "..", "samples", "auth_sample.log")
        with tempfile.TemporaryDirectory() as tmp:
            j, c = os.path.join(tmp, "r.json"), os.path.join(tmp, "r.csv")
            code = sentinel.main([sample, "--year", "2026", "--json", j, "--csv", c])
            self.assertEqual(code, 1)
            self.assertTrue(os.path.getsize(j) > 0 and os.path.getsize(c) > 0)

    def test_missing_file_returns_2(self):
        self.assertEqual(sentinel.main(["/no/such/file.log"]), 2)


if __name__ == "__main__":
    unittest.main()

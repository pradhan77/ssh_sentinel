import json
import unittest
from datetime import datetime

from analyzer import classify_ip

class TestIPClassification(unittest.TestCase):
    def test_loopback_ipv4(self):
        self.assertEqual(classify_ip("127.0.0.1"), "Loopback")

    def test_loopback_ipv6(self):
        self.assertEqual(classify_ip("::1"), "Loopback")

    def test_private_ipv4(self):
        self.assertEqual(classify_ip("192.168.1.50"), "Internal")

    def test_documentation_ipv4_ranges(self):
        for ip in ("192.0.2.1", "198.51.100.77", "203.0.113.55"):
            with self.subTest(ip=ip):
                self.assertEqual(classify_ip(ip), "Documentation")

    def test_documentation_ipv6_range(self):
        self.assertEqual(classify_ip("2001:db8::1"), "Documentation")

    def test_public_ipv4(self):
        self.assertEqual(classify_ip("8.8.8.8"), "External")

    def test_link_local_ipv4(self):
        self.assertEqual(classify_ip("169.254.1.1"), "Link-local")


from analyzer import LogAnalyzer, parse_timestamp


def failed(ts, ip, user="root", pid=1000, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return f"{ts} srv sshd[{pid}]: Failed password for {who} from {ip} port 22 ssh2"


def accepted(ts, ip, user="alice", method="password", pid=2000):
    return f"{ts} srv sshd[{pid}]: Accepted {method} for {user} from {ip} port 22 ssh2"


class TestParsing(unittest.TestCase):
    def test_iso_timestamp_with_offset(self):
        ts = parse_timestamp("2026-10-24T16:11:02+0545 kali sshd[1]: x", 2026)
        self.assertEqual(ts, datetime(2026, 10, 24, 16, 11, 2))

    def test_syslog_timestamp_uses_given_year(self):
        ts = parse_timestamp("Jan 30 14:22:33 srv sshd[1]: x", 2025)
        self.assertEqual(ts, datetime(2025, 1, 30, 14, 22, 33))

    def test_no_timestamp_returns_none(self):
        self.assertIsNone(parse_timestamp("random garbage line", 2026))

    def test_invalid_date_returns_none(self):
        self.assertIsNone(parse_timestamp("2026-13-45T10:00:00 srv x", 2026))


class TestBasics(unittest.TestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer(threshold=1, year=2026)

    def test_empty_input(self):
        alerts, logins = self.analyzer.analyze_logs_text([])
        self.assertEqual(alerts, [])
        self.assertEqual(logins, [])

    def test_irrelevant_lines_ignored(self):
        lines = [
            "Jan 30 14:22:33 server systemd[123]: Started Session 7 of user pradhan.",
            "something completely unrelated",
            "",
        ]
        alerts, logins = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(alerts, [])
        self.assertEqual(logins, [])
        self.assertEqual(self.analyzer.skipped_lines, 0)

    def test_line_without_timestamp_is_skipped_and_counted(self):
        lines = [
            "Failed password for testuser from 172.16.0.99 port 2222 ssh2",
            "Accepted password for bob from 10.20.30.40 port 22 ssh2",
        ]
        alerts, logins = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(alerts, [])
        self.assertEqual(logins, [])
        self.assertEqual(self.analyzer.skipped_lines, 2)


class TestBruteForce(unittest.TestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer(threshold=1, year=2026)

    def test_single_failure_is_low(self):
        alerts, _ = self.analyzer.analyze_logs_text(
            [failed("Jan 30 15:44:12", "203.0.113.55")]
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].level, "LOW")
        self.assertEqual(alerts[0].ip, "203.0.113.55")
        self.assertEqual(alerts[0].failures, 1)
        self.assertIn("Failed Attempts: 1", alerts[0].render())

    def test_levels_follow_burst_size(self):
        lines = []
        for i in range(6):  # 6 in 12 seconds -> HIGH
            lines.append(failed(f"Jan 30 16:01:{i * 2:02d}", "192.0.2.10", pid=2000 + i))
        for i in range(4):  # 4 in 6 seconds -> MEDIUM
            lines.append(failed(f"Jan 30 16:02:{i * 2:02d}", "198.51.100.77", pid=2100 + i))
        lines.append(failed("Jan 30 16:03:40", "45.79.111.33", pid=2200))  # 1 -> LOW

        alerts, _ = self.analyzer.analyze_logs_text(lines)
        by_ip = {a.ip: a for a in alerts}
        self.assertEqual(by_ip["192.0.2.10"].level, "HIGH")
        self.assertEqual(by_ip["198.51.100.77"].level, "MEDIUM")
        self.assertEqual(by_ip["45.79.111.33"].level, "LOW")
        self.assertEqual(alerts[0].ip, "192.0.2.10")  # most severe first

    def test_slow_failures_do_not_reach_high(self):
        # 6 failures, one every 5 minutes: same total as a burst, very different risk
        lines = [
            failed(f"Jan 30 16:{m:02d}:00", "203.0.113.9", pid=3000 + m)
            for m in range(0, 30, 5)
        ]
        alerts, _ = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(alerts[0].failures, 6)
        self.assertEqual(alerts[0].peak, 1)
        self.assertEqual(alerts[0].level, "LOW")

    def test_pam_line_alone_is_counted(self):
        line = (
            "Jan 30 17:12:45 server sshd[3344]: pam_unix(sshd:auth): "
            "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
            "rhost=203.0.113.88  user=root"
        )
        alerts, _ = self.analyzer.analyze_logs_text([line])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].ip, "203.0.113.88")
        self.assertEqual(alerts[0].failures, 1)

    def test_pam_and_failed_password_from_same_pid_count_once(self):
        lines = [
            "Jan 30 17:12:45 server sshd[3344]: pam_unix(sshd:auth): "
            "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
            "rhost=203.0.113.88  user=root",
            failed("Jan 30 17:12:47", "203.0.113.88", pid=3344),
        ]
        alerts, _ = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(alerts[0].failures, 1)

    def test_invalid_user_line_is_not_double_counted(self):
        lines = [
            "Jan 30 18:00:01 srv sshd[4000]: Invalid user admin from 203.0.113.20 port 2222",
            failed("Jan 30 18:00:03", "203.0.113.20", user="admin", pid=4000, invalid=True),
        ]
        alerts, _ = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(alerts[0].failures, 1)
        self.assertEqual(alerts[0].users, ["admin"])

    def test_ipv6_source(self):
        alerts, _ = self.analyzer.analyze_logs_text(
            [failed("Jan 30 18:10:00", "2001:db8::1")]
        )
        self.assertEqual(alerts[0].ip, "2001:db8::1")

    def test_threshold_respected(self):
        analyzer = LogAnalyzer(threshold=4, year=2026)
        lines = [failed("Jan 30 20:00:01", "1.2.3.4", pid=5000 + i) for i in range(5)]
        lines.append(failed("Jan 30 20:00:02", "5.6.7.8", pid=6000))
        alerts, _ = analyzer.analyze_logs_text(lines)
        self.assertEqual([a.ip for a in alerts], ["1.2.3.4"])
        self.assertEqual(alerts[0].failures, 5)
        self.assertEqual(alerts[0].level, "HIGH")

    def test_users_list_is_collected(self):
        lines = [
            failed("Jan 30 21:00:00", "203.0.113.30", user="root", pid=1),
            failed("Jan 30 21:00:01", "203.0.113.30", user="admin", pid=2),
            failed("Jan 30 21:00:02", "203.0.113.30", user="deploy-bot", pid=3),
        ]
        alerts, _ = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(alerts[0].users, ["admin", "deploy-bot", "root"])


class TestLogins(unittest.TestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer(threshold=1, year=2026)

    def test_password_and_key_logins_parsed(self):
        lines = [
            accepted("Jan 30 18:05:22", "192.168.1.77", user="pradhan"),
            accepted("Jan 30 18:07:10", "10.10.5.33", user="deploy-ci", method="publickey"),
        ]
        _, logins = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(len(logins), 2)
        self.assertEqual(logins[0].user, "pradhan")
        self.assertEqual(logins[1].user, "deploy-ci")
        self.assertEqual(logins[1].method, "publickey")
        self.assertIn("Successful SSH Login", logins[0].render())

    def test_login_after_many_failures_is_critical(self):
        lines = [
            failed(f"Jan 30 22:00:{i:02d}", "203.0.113.55", user="root", pid=7000 + i)
            for i in range(0, 12, 2)
        ]
        lines.append(accepted("Jan 30 22:01:00", "203.0.113.55", user="root"))
        alerts, logins = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(alerts[0].level, "CRITICAL")
        self.assertEqual(alerts[0].ip, "203.0.113.55")
        self.assertIn("root", alerts[0].note)
        self.assertEqual(len(logins), 1)

    def test_login_after_few_failures_is_not_critical(self):
        lines = [
            failed("Jan 30 22:00:00", "192.168.1.77", user="alice", pid=1),
            failed("Jan 30 22:00:05", "192.168.1.77", user="alice", pid=2),
            accepted("Jan 30 22:00:10", "192.168.1.77", user="alice"),
        ]
        alerts, _ = self.analyzer.analyze_logs_text(lines)
        self.assertNotIn("CRITICAL", [a.level for a in alerts])

    def test_login_from_different_ip_is_not_critical(self):
        lines = [
            failed(f"Jan 30 22:00:{i:02d}", "203.0.113.55", pid=8000 + i) for i in range(8)
        ]
        lines.append(accepted("Jan 30 22:00:30", "192.168.1.5", user="alice"))
        alerts, _ = self.analyzer.analyze_logs_text(lines)
        self.assertNotIn("CRITICAL", [a.level for a in alerts])

    def test_failures_older_than_lookback_do_not_correlate(self):
        lines = [
            failed(f"Jan 30 08:00:{i:02d}", "203.0.113.55", pid=9000 + i) for i in range(8)
        ]
        lines.append(accepted("Jan 30 20:00:00", "203.0.113.55", user="root"))
        alerts, _ = self.analyzer.analyze_logs_text(lines)
        self.assertNotIn("CRITICAL", [a.level for a in alerts])


class TestOutput(unittest.TestCase):
    def test_to_dict_is_json_serializable(self):
        analyzer = LogAnalyzer(year=2026)
        lines = [
            failed("Jan 30 22:00:00", "203.0.113.55", pid=1),
            accepted("Jan 30 22:05:00", "203.0.113.55", user="root"),
        ]
        alerts, logins = analyzer.analyze_logs_text(lines)
        payload = json.dumps(
            {"alerts": [a.to_dict() for a in alerts], "logins": [e.to_dict() for e in logins]}
        )
        self.assertIn("203.0.113.55", payload)


if __name__ == "__main__":
    unittest.main()

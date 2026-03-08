import unittest
from collections import defaultdict

# CHANGE THIS to your actual filename (without .py)
from ssh_sentinel import LogAnalyzer     # ← fix this line !!


class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = LogAnalyzer(threshold=1)

    # ────────────────────────────────────────────────
    # Basic / empty / irrelevant
    # ────────────────────────────────────────────────

    def test_empty_input(self):
        alerts, successes = self.analyzer.analyze_logs_text([])
        self.assertEqual(alerts, [])
        self.assertEqual(successes, [])

    def test_only_irrelevant_lines(self):
        lines = [
            "Jan 30 14:22:33 server systemd[123]: Started Session 7 of user pradhan.",
            "Jan 30 14:23:10 server kernel: some random kernel message",
            "something completely unrelated",
            "",
        ]
        alerts, successes = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(alerts, [])
        self.assertEqual(successes, [])

    # ────────────────────────────────────────────────
    # Failed attempts
    # ────────────────────────────────────────────────

    def test_single_failed_password(self):
        lines = [
            'Jan 30 15:44:12 server sshd[12345]: Failed password for root from 203.0.113.55 port 2222 ssh2'
        ]
        alerts, successes = self.analyzer.analyze_logs_text(lines)

        self.assertEqual(len(successes), 0)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertIn("[LOW]", alert)
        self.assertIn("203.0.113.55", alert)
        self.assertIn("Failed Attempts: 1", alert)
        self.assertIn("Jan 30 15:44:12", alert)

    def test_multiple_failed_attempts_different_levels(self):
        lines = [
            # IP1: 6 → HIGH
            'Jan 30 16:01:01 srv sshd[2001]: Failed password for root from 192.168.55.10 port 22 ssh2',
            'Jan 30 16:01:03 srv sshd[2002]: Failed password for root from 192.168.55.10 port 22 ssh2',
            'Jan 30 16:01:05 srv sshd[2003]: Failed password for root from 192.168.55.10 port 22 ssh2',
            'Jan 30 16:01:07 srv sshd[2004]: Failed password for root from 192.168.55.10 port 22 ssh2',
            'Jan 30 16:01:09 srv sshd[2005]: Failed password for root from 192.168.55.10 port 22 ssh2',
            'Jan 30 16:01:11 srv sshd[2006]: Failed password for root from 192.168.55.10 port 22 ssh2',

            # IP2: 4 → MEDIUM
            'Jan 30 16:02:20 srv sshd[2101]: Failed password for admin from 198.51.100.77 port 1234 ssh2',
            'Jan 30 16:02:22 srv sshd[2102]: Failed password for admin from 198.51.100.77 port 1234 ssh2',
            'Jan 30 16:02:24 srv sshd[2103]: Failed password for admin from 198.51.100.77 port 1234 ssh2',
            'Jan 30 16:02:26 srv sshd[2104]: Failed password for admin from 198.51.100.77 port 1234 ssh2',

            # IP3: 1 → LOW
            'Jan 30 16:03:40 srv sshd[2201]: Failed password for git from 45.79.111.33 port 2222 ssh2',
        ]

        alerts, _ = self.analyzer.analyze_logs_text(lines)

        self.assertEqual(len(alerts), 3)

        text = "\n".join(alerts).lower()
        self.assertIn("192.168.55.10", text)
        self.assertIn("failed attempts: 6", text)
        self.assertIn("high", text)
        self.assertIn("198.51.100.77", text)
        self.assertIn("failed attempts: 4", text)
        self.assertIn("medium", text)
        self.assertIn("45.79.111.33", text)
        self.assertIn("failed attempts: 1", text)
        self.assertIn("low", text)

    def test_pam_authentication_failure(self):
        line = (
            "Jan 30 17:12:45 server sshd[3344]: "
            "pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.88  user=root"
        )
        alerts, _ = self.analyzer.analyze_logs_text([line])
        self.assertEqual(len(alerts), 1)
        self.assertIn("203.0.113.88", alerts[0])
        self.assertIn("Failed Attempts: 1", alerts[0])
        self.assertIn("LOW", alerts[0])

    # ────────────────────────────────────────────────
    # Successful logins
    # ────────────────────────────────────────────────

    def test_successful_logins_password_and_key(self):
        lines = [
            'Jan 30 18:05:22 server sshd[5566]: Accepted password for pradhan from 192.168.1.77 port 54321 ssh2',
            'Jan 30 18:07:10 server sshd[5567]: Accepted publickey for deploy from 10.10.5.33 port 22 ssh2: RSA SHA256:xxxx'
        ]

        _, successes = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(len(successes), 2)

        s1, s2 = successes
        self.assertIn("pradhan", s1)
        self.assertIn("192.168.1.77", s1)
        self.assertIn("Jan 30 18:05:22", s1)
        self.assertIn("Successful SSH Login", s1)

        self.assertIn("deploy", s2)
        self.assertIn("10.10.5.33", s2)
        self.assertIn("Jan 30 18:07:10", s2)
        self.assertIn("Successful SSH Login", s2)

    # ────────────────────────────────────────────────
    # Timestamp fallback / edge cases — adapted to current buggy behavior
    # ────────────────────────────────────────────────

    def test_line_without_valid_timestamp(self):
        lines = [
            "random garbage line without date",
            "Failed password for testuser from 172.16.0.99 port 2222 ssh2",
            "another invalid line",
            "Accepted password for bob from 10.20.30.40 port 22 ssh2",
        ]

        alerts, successes = self.analyzer.analyze_logs_text(lines)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(successes), 1)

        # Current behavior (first 3 words become timestamp)
        self.assertIn("Failed password for", alerts[0])
        self.assertIn("172.16.0.99", alerts[0])

        self.assertIn("Accepted password for", successes[0])   # first 3 words
        self.assertIn("10.20.30.40", successes[0])

    def test_mixed_valid_and_invalid_timestamps(self):
        lines = [
            'Jan 30 19:10:01 srv sshd[3001]: Failed password for root from 203.0.113.200 port 22 ssh2',
            'invalid line Failed password for alice from 192.168.100.50 port 2222 ssh2',
            'Jan 30 19:11:05 srv sshd[3002]: Failed password for root from 203.0.113.200 port 22 ssh2',
        ]

        alerts, _ = self.analyzer.analyze_logs_text(lines)

        # Current buggy behavior → two alerts (two different "timestamps" → two different keys in dict)
        self.assertEqual(len(alerts), 2)

        text = "\n".join(alerts)
        self.assertIn("203.0.113.200", text)
        self.assertIn("Jan 30 19:10:01", text)          # valid
        self.assertIn("Jan 30 19:11:05", text)          # valid
        self.assertIn("invalid line Failed", text)      # invalid line used as ts
        self.assertIn("192.168.100.50", text)

    def test_threshold_respected(self):
        self.analyzer.threshold = 4

        lines = [
            'Jan 30 20:00:01 srv sshd[4001]: Failed password for root from 1.2.3.4 port 22 ssh2'
        ] * 5   # 5 attempts

        alerts, _ = self.analyzer.analyze_logs_text(lines)
        self.assertEqual(len(alerts), 1)
        self.assertIn("Failed Attempts: 5", alerts[0])
        self.assertIn("HIGH", alerts[0])


if __name__ == '__main__':
    unittest.main()

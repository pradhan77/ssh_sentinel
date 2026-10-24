
#!/usr/bin/env python3
"""SSH Sentinel: SSH brute-force detection and login correlation."""

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
TIME_FMT = "%Y-%m-%d %H:%M:%S UTC"
MAX_USERS_SHOWN = 10

ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(Z|[+-]\d{2}:?\d{2})?")
SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
PID_RE = re.compile(r"sshd(?:-session)?\[(\d+)\]")

FAILED_RE = re.compile(
    r"Failed (?:password|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+)"
)
PAM_RE = re.compile(
    r"authentication failure;.*?rhost=(?P<ip>[0-9A-Fa-f:.]+)"
    r"(?:\s+user=(?P<user>\S+))?"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>[0-9A-Fa-f:.]+)"
)


def parse_timestamp(line, year):
    """Parse ISO and traditional syslog timestamps, returning UTC-aware datetimes."""
    try:
        match = ISO_RE.match(line)
        if match:
            date_part, time_part, offset = match.groups()
            value = f"{date_part}T{time_part}"

            if offset == "Z":
                value += "+00:00"
            elif offset:
                if len(offset) == 5:
                    offset = offset[:3] + ":" + offset[3:]
                value += offset

            timestamp = datetime.fromisoformat(value)
            if timestamp.tzinfo is None:
                timestamp = timestamp.astimezone()
            return timestamp.astimezone(timezone.utc)

        match = SYSLOG_RE.match(line)
        if match:
            timestamp = datetime.strptime(
                f"{year} {match.group(1)} {match.group(2)} {match.group(3)}",
                "%Y %b %d %H:%M:%S",
            )
            return timestamp.astimezone(timezone.utc)

    except (ValueError, OverflowError):
        return None

    return None


def clean_ip(raw):
    """Validate and normalize an IP address."""
    try:
        return str(ipaddress.ip_address(raw.rstrip(".:")))
    except ValueError:
        return None



def classify_ip(ip):
    """Classify an IP address without treating documentation ranges as internal."""
    address = ipaddress.ip_address(ip)

    if address.is_loopback:
        return "Loopback"

    if address.is_link_local:
        return "Link-local"

    # Reserved for documentation and examples.
    documentation_networks = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    )

    if any(address in network for network in documentation_networks):
        return "Documentation"

    if address.is_private:
        return "Internal"

    if not address.is_global:
        return "Special-use"

    return "External"



@dataclass
class LoginEvent:
    time: datetime
    user: str
    ip: str
    method: str

    @property
    def ip_scope(self):
        return classify_ip(self.ip)

    def render(self):
        return (
            "[INFO] Successful SSH Login\n"
            f"Time: {self.time.strftime(TIME_FMT)}\n"
            f"User: {self.user}\n"
            f"IP Address: {self.ip}\n"
            f"IP Classification: {self.ip_scope}\n"
            f"Method: {self.method}\n"
            f"{'-' * 55}"
        )

    def to_dict(self):
        return {
            "time": self.time.isoformat(),
            "user": self.user,
            "ip": self.ip,
            "ip_scope": self.ip_scope,
            "method": self.method,
        }


@dataclass
class Alert:
    level: str
    ip: str
    failures: int
    peak: int
    first_seen: datetime
    last_seen: datetime
    users: list = field(default_factory=list)
    note: str = ""

    @property
    def title(self):
        if self.level == "CRITICAL":
            return "Possible Compromise (login succeeded after failures)"
        return "Brute Force Attempt Detected"

    @property
    def ip_scope(self):
        return classify_ip(self.ip)

    def render(self):
        shown = self.users[:MAX_USERS_SHOWN]
        users = ", ".join(shown) if shown else "n/a"

        if len(self.users) > MAX_USERS_SHOWN:
            users += f" (+{len(self.users) - MAX_USERS_SHOWN} more)"

        lines = [
            f"[{self.level}] {self.title}",
            f"IP Address: {self.ip}",
            f"IP Classification: {self.ip_scope}",
            f"Failed Attempts: {self.failures}",
            f"Peak Burst: {self.peak} within the detection window",
            f"First Seen: {self.first_seen.strftime(TIME_FMT)}",
            f"Last Seen: {self.last_seen.strftime(TIME_FMT)}",
            f"Users Tried: {users}",
        ]

        if self.note:
            lines.append(f"Note: {self.note}")

        lines.append("-" * 55)
        return "\n".join(lines)

    def to_dict(self):
        return {
            "level": self.level,
            "title": self.title,
            "ip": self.ip,
            "ip_scope": self.ip_scope,
            "failures": self.failures,
            "peak": self.peak,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "users": self.users,
            "note": self.note,
        }


class LogAnalyzer:
    """Analyze SSH logs for brute-force attempts and suspicious logins."""

    def __init__(
        self,
        threshold=1,
        window_seconds=60,
        medium_peak=3,
        high_peak=5,
        correlation_window=900,
        correlation_min_failures=5,
        year=None,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.medium_peak = medium_peak
        self.high_peak = high_peak
        self.correlation_window = correlation_window
        self.correlation_min_failures = correlation_min_failures
        self.year = year or datetime.now().year
        self.alerts = []
        self.logins = []
        self.skipped_lines = 0

    def analyze_logs_text(self, lines):
        failures, logins, skipped = self._parse(lines)

        brute_force = self._brute_force_alerts(failures)
        critical = self._correlation_alerts(failures, logins)

        # Avoid a duplicate brute-force alert when the same IP has a
        # critical login-after-failures alert.
        critical_ips = {alert.ip for alert in critical}
        alerts = [
            alert for alert in brute_force
            if alert.ip not in critical_ips
        ]
        alerts.extend(critical)
        alerts.sort(key=lambda a: (LEVEL_ORDER[a.level], -a.failures))

        self.alerts = alerts
        self.logins = sorted(logins, key=lambda e: e.time)
        self.skipped_lines = skipped
        return self.alerts, self.logins

    def _parse(self, lines):
        raw = []
        logins = []
        skipped = 0

        for line in lines:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue

            failed = FAILED_RE.search(line)
            pam = None if failed else PAM_RE.search(line)
            accepted = None if (failed or pam) else ACCEPTED_RE.search(line)
            match = failed or pam or accepted

            if not match:
                continue

            timestamp = parse_timestamp(line, self.year)
            ip = clean_ip(match.group("ip"))

            if timestamp is None or ip is None:
                skipped += 1
                continue

            pid_match = PID_RE.search(line)
            pid = pid_match.group(1) if pid_match else None

            if accepted:
                logins.append(
                    LoginEvent(
                        timestamp,
                        accepted.group("user"),
                        ip,
                        accepted.group("method"),
                    )
                )
            else:
                user = match.group("user") or ""
                raw.append(
                    (timestamp, ip, user, pid, "failed" if failed else "pam")
                )

        # Avoid counting matching PAM and failed-password events twice.
        failed_pids = {
            pid for _, _, _, pid, source in raw
            if source == "failed" and pid
        }

        failures = defaultdict(list)
        for timestamp, ip, user, pid, source in raw:
            if source == "pam" and pid and pid in failed_pids:
                continue
            failures[ip].append((timestamp, user))

        for ip in failures:
            failures[ip].sort(key=lambda event: event[0])

        return failures, logins, skipped

    @staticmethod
    def _peak(times, window):
        """Find the largest event count in any sliding time window."""
        best = 0
        start = 0

        for end, timestamp in enumerate(times):
            while timestamp - times[start] > window:
                start += 1
            best = max(best, end - start + 1)

        return best

    def _level_for(self, peak):
        if peak >= self.high_peak:
            return "HIGH"
        if peak >= self.medium_peak:
            return "MEDIUM"
        return "LOW"

    def _brute_force_alerts(self, failures):
        window = timedelta(seconds=self.window_seconds)
        alerts = []

        for ip, events in failures.items():
            if len(events) < self.threshold:
                continue

            times = sorted(timestamp for timestamp, _ in events)
            peak = self._peak(times, window)

            alerts.append(
                Alert(
                    level=self._level_for(peak),
                    ip=ip,
                    failures=len(events),
                    peak=peak,
                    first_seen=times[0],
                    last_seen=times[-1],
                    users=sorted({user for _, user in events if user}),
                )
            )

        return alerts

    def _correlation_alerts(self, failures, logins):
        lookback = timedelta(seconds=self.correlation_window)
        window = timedelta(seconds=self.window_seconds)
        alerts = []
        seen = set()

        for login in sorted(logins, key=lambda event: event.time):
            key = (login.ip, login.user)
            if key in seen:
                continue

            prior = [
                (timestamp, user)
                for timestamp, user in failures.get(login.ip, [])
                if login.time - lookback <= timestamp <= login.time
            ]

            if len(prior) < self.correlation_min_failures:
                continue

            seen.add(key)
            times = sorted(timestamp for timestamp, _ in prior)

            alerts.append(
                Alert(
                    level="CRITICAL",
                    ip=login.ip,
                    failures=len(prior),
                    peak=self._peak(times, window),
                    first_seen=times[0],
                    last_seen=times[-1],
                    users=sorted({user for _, user in prior if user}),
                    note=(
                        f"Login accepted for '{login.user}' ({login.method}) at "
                        f"{login.time.strftime(TIME_FMT)} after {len(prior)} failures "
                        f"in the previous {self.correlation_window // 60} minutes"
                    ),
                )
            )

        return alerts


def read_file(path):
    """Read log lines from a file."""
    with open(path, encoding="utf-8", errors="ignore") as handle:
        return handle.read().splitlines()


def read_journal(max_lines=2000, since=None):
    """Read SSH authentication entries from systemd journal."""
    command = [
        "journalctl",
        "-u", "ssh",
        "-u", "sshd",
        "--no-pager",
        "-o", "short-iso",
    ]

    if since:
        command.extend(["--since", since])
    else:
        command.extend(["-n", str(max_lines)])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("journalctl was not found on this system.") from exc

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "journalctl failed")

    return result.stdout.splitlines()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="SSH Sentinel - SSH brute-force detector"
    )
    parser.add_argument("logfile", nargs="?", help="auth log file to analyze")
    parser.add_argument("--journal", action="store_true", help="read from journald")
    parser.add_argument(
        "--since",
        help='only read journal entries since a time, e.g. "2 hours ago"',
    )
    parser.add_argument("--window", type=int, default=60, help="burst window in seconds")
    parser.add_argument("--year", type=int, default=None, help="year for syslog timestamps")
    parser.add_argument("--threshold", type=int, default=1, help="minimum failures per IP")
    parser.add_argument("--json", action="store_true", help="print JSON output")
    args = parser.parse_args(argv)

    if bool(args.logfile) == bool(args.journal):
        parser.error("give either a log file or --journal")
    if args.since and not args.journal:
        parser.error("--since can only be used with --journal")
    if args.window <= 0:
        parser.error("--window must be greater than zero")
    if args.threshold <= 0:
        parser.error("--threshold must be greater than zero")

    try:
        lines = (
            read_journal(since=args.since)
            if args.journal
            else read_file(args.logfile)
        )
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    analyzer = LogAnalyzer(
        threshold=args.threshold,
        window_seconds=args.window,
        year=args.year,
    )
    alerts, logins = analyzer.analyze_logs_text(lines)

    if args.json:
        print(json.dumps({
            "alerts": [alert.to_dict() for alert in alerts],
            "logins": [login.to_dict() for login in logins],
            "skipped_lines": analyzer.skipped_lines,
        }, indent=2))
        return 0

    for alert in alerts:
        print(alert.render())
    for login in logins:
        print(login.render())

    print(
        f"{len(alerts)} alert(s), {len(logins)} successful login(s), "
        f"{analyzer.skipped_lines} line(s) skipped "
        "(no usable timestamp or IP)"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)

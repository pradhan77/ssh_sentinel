# SSH Sentinel

A small Python tool that detects SSH brute-force attacks in OpenSSH logs and flags the case a SOC analyst worries about most: **a login that succeeds right after a burst of failures from the same IP**.

It runs as a Tkinter desktop monitor or as a command-line tool that can print JSON for other tooling (for example an n8n or SIEM pipeline).

## Features

- **Windowed detection.** Severity depends on how fast failures arrive (a sliding window), not just how many there are in total.
- **Success-after-failure correlation.** A successful login from an IP that just failed repeatedly raises a `CRITICAL` alert.
- **No double counting.** One failed login often writes both a `Failed password` line and a PAM `authentication failure` line. Lines from the same sshd process are counted once.
- **Real timestamps.** Parses ISO timestamps (`journalctl -o short-iso`) and classic syslog timestamps. Lines with no usable timestamp are skipped and counted, not guessed at.
- **IPv4 and IPv6**, validated with Python's `ipaddress` module.
- **Headless core.** `analyzer.py` has no GUI imports, so tests and the CLI run on any machine.
- **GUI** with severity filters, colored output, live monitoring and background log reads so the window never freezes.

## Detection logic

| Level | Condition (defaults) |
|-------|----------------------|
| LOW | Failures from one IP, fewer than 3 inside any 60 second window |
| MEDIUM | 3 or more failures inside 60 seconds |
| HIGH | 5 or more failures inside 60 seconds |
| CRITICAL | A successful login from an IP that had 5 or more failures in the previous 15 minutes |

All thresholds are constructor arguments of `LogAnalyzer` (`window_seconds`, `medium_peak`, `high_peak`, `correlation_window`, `correlation_min_failures`).

## Quick start

```
git clone https://github.com/pradhan77/ssh_sentinel.git
cd ssh_sentinel
python3 -m unittest -v
python3 analyzer.py sample_logs/auth_sample.log
python3 ssh_sentinel.py
```

The GUI needs Tkinter (`sudo apt install python3-tk` on Debian or Kali). Reading live logs uses `journalctl`, so your user needs access to the journal (membership of the `systemd-journal` or `adm` group).

### Command line

```
python3 analyzer.py /var/log/auth.log
python3 analyzer.py --journal
python3 analyzer.py sample_logs/auth_sample.log --json
python3 analyzer.py auth.log --window 30 --threshold 3 --year 2026
```

`--year` matters only for classic syslog timestamps, which do not contain a year.

## Sample output

Running the analyzer on `sample_logs/auth_sample.log` (synthetic data using documentation IP ranges):

```
[CRITICAL] Possible Compromise (login succeeded after failures)
IP Address: 203.0.113.55
Failed Attempts: 8
Peak Burst: 8 within the detection window
First Seen: 2026-10-24 10:00:00
Last Seen: 2026-10-24 10:00:21
Users Tried: admin, git, oracle, root, test, ubuntu
Note: Login accepted for 'root' (password) at 2026-10-24 10:00:30 after 8 failures in the previous 15 minutes
```

The same log also contains a slow guessing run from `198.51.100.77` (4 failures spread over 22 minutes, peak burst 1, so only `LOW`), an IPv6 burst, and normal logins that correctly stay quiet.

## Project layout

```
analyzer.py           detection engine and CLI (no GUI imports)
ssh_sentinel.py       Tkinter front end
test_analyzer.py      29 unit tests
sample_logs/          synthetic log for demos and the README
```

## Limitations and next steps

- Tracks brute force per source IP. Distributed attacks that spread attempts across many IPs are not correlated.
- Slow "low and slow" guessing shows as `LOW`; a longer second window would catch it.
- Timezone offsets in ISO timestamps are ignored, so mixing logs from different timezones can skew windows.
- No GeoIP or reputation lookups, and no automatic blocking.
- Planned: JSON alerts posted to a webhook, so findings can feed an automated response pipeline.

## What I learned

- Brute force is a rate, not a count. A burst of 6 failures in 12 seconds and 6 failures across 30 minutes are different problems.
- Correlating two event types (failures, then a success) finds the compromise that a plain counter never would.
- Separating the detection engine from the interface made the logic easy to unit test.

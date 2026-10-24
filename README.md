# SSH Sentinel

**A Python-based SSH brute-force detection tool for defensive security monitoring.**

SSH Sentinel analyzes OpenSSH authentication logs to identify suspicious login activity, classify brute-force attempts by severity, and detect a potentially compromised account when a successful login follows repeated failures from the same IP address.

It includes a command-line interface (CLI), a Tkinter graphical user interface (GUI), structured JSON output, and a unit-tested detection engine.

## Features

- **Sliding-window detection:** Identifies bursts of failed SSH authentication attempts within a configurable time window.
- **Severity classification:** Assigns LOW, MEDIUM, HIGH, or CRITICAL severity based on observed activity and login correlation.
- **Success-after-failure correlation:** Raises a CRITICAL alert when a successful login follows a sufficient number of failed attempts from the same IP address within the configured lookback period.
- **Duplicate-event handling:** Avoids counting certain PAM authentication failures twice when they correspond to a failed-password event from the same SSH process.
- **IPv4 and IPv6 support:** Uses Python's `ipaddress` module to validate and classify IP addresses.
- **Timestamp parsing:** Supports ISO-style timestamps and traditional syslog timestamps. ISO timestamps with timezone offsets are normalized to UTC by the current implementation; traditional syslog timestamps require a supplied year and use the machine's local timezone assumption.
- **CLI and JSON output:** Analyze log files or journal entries and produce structured output for further processing.
- **Tkinter GUI:** Provides severity filtering, colored alerts, and live monitoring with background log reads.
- **Testable architecture:** Keeps the analysis engine separate from the GUI so the core logic can be tested independently.

## How It Works

SSH Sentinel follows a simple detection workflow:

1. Read SSH authentication logs from a file or the system journal.
2. Parse relevant authentication events, including failed attempts and accepted logins.
3. Group failed attempts by source IP address.
4. Calculate the peak number of failures within the configured sliding time window.
5. Assign severity according to the configured thresholds.
6. Correlate successful logins with preceding failures from the same IP address.
7. Produce readable alerts or JSON output.

## Detection Logic

The default settings are:

| Severity | Condition |
|---|---|
| LOW | Failed attempts from one IP, with a peak below 3 in a 60-second window |
| MEDIUM | At least 3 failures from one IP in a 60-second window |
| HIGH | At least 5 failures from one IP in a 60-second window |
| CRITICAL | A successful login from an IP with at least 5 preceding failures in the previous 15 minutes |

**Note:** HIGH takes precedence over MEDIUM when the higher threshold is reached. A CRITICAL correlation alert takes precedence over the ordinary brute-force alert for the same source IP.

These thresholds are configurable through the `LogAnalyzer` constructor and CLI options where supported.

## Requirements

- Python 3
- Linux environment recommended for live SSH log monitoring
- Tkinter for the graphical interface
- `journalctl` for reading system journal entries

On Kali Linux or Debian, install Tkinter if necessary:

```bash
sudo apt update
sudo apt install python3-tk
```

Live journal monitoring requires suitable permissions to read the system journal. Depending on your distribution, this may involve membership in the `systemd-journal` or `adm` group.

## Installation

Clone the repository:

```bash
git clone https://github.com/pradhan77/ssh_sentinel.git
cd ssh_sentinel
```

Run the unit tests:

```bash
python3 -m unittest -v
```

The current test suite contains **31 unit tests**, covering parsing, detection thresholds, severity classification, IP handling, event deduplication, successful-login correlation, timestamp handling, and JSON serialization.

## Usage

### 1. Analyze a sample log file

```bash
python3 analyzer.py sample_logs/auth_sample.log
```

### 2. Analyze a log file

For systems that maintain an authentication log at `/var/log/auth.log`:

```bash
python3 analyzer.py /var/log/auth.log
```

The path depends on your operating system and logging configuration.

### 3. Read the system journal

```bash
python3 analyzer.py --journal
```

### 4. Generate JSON output

```bash
python3 analyzer.py sample_logs/auth_sample.log --json
```

JSON output is useful for structured processing, testing, or future integration with SIEM and SOAR workflows.

### 5. Configure the detection threshold

For example, set the failure threshold to 3 and use a 30-second window:

```bash
python3 analyzer.py auth.log --window 30 --threshold 3 --year 2026
```

The `--year` option applies to traditional syslog timestamps that do not include a year.

### 6. Launch the graphical interface

```bash
python3 ssh_sentinel.py
```

The GUI provides a visual way to inspect alerts, filter by severity, and monitor authentication activity.

## Example Alert

The following is an illustrative example using synthetic log data and documentation-only IP addresses:

```text
[CRITICAL] Possible Compromise (login succeeded after failures)
IP Address: 203.0.113.55
Failed Attempts: 8
Peak Burst: 8 within the detection window
First Seen: 2026-10-24 10:00:00 UTC
Last Seen: 2026-10-24 10:00:21 UTC
Users Tried: admin, git, oracle, root, test, ubuntu
Note: Login accepted for 'root' (password) at 2026-10-24 10:00:30 UTC after 8 failures in the previous 15 minutes
```

This alert indicates that the same source IP generated multiple failed authentication attempts before a successful login. Such behavior deserves investigation, but it does not by itself prove that an account was compromised.

The sample log also demonstrates slower guessing attempts and IPv6 activity.

## Project Structure

```text
ssh_sentinel/
├── analyzer.py
├── ssh_sentinel.py
├── test_analyzer.py
├── sample_logs/
│   └── auth_sample.log
├── .gitignore
└── README.md
```

| File or directory | Purpose |
|---|---|
| `analyzer.py` | Log parsing, detection logic, and CLI |
| `ssh_sentinel.py` | Tkinter graphical interface |
| `test_analyzer.py` | Unit tests for the detection engine |
| `sample_logs/` | Synthetic authentication logs for testing and demonstrations |
| `.gitignore` | Excludes files that should not be tracked by Git |

## Testing

Run the complete test suite:

```bash
python3 -m unittest -v
```

The current suite contains 31 tests for:

- Empty input and irrelevant log entries
- Timestamp parsing and invalid dates
- Failed-password and PAM event handling
- IPv4 and IPv6 source addresses
- Severity thresholds and sliding-window behavior
- Successful-login correlation
- JSON serialization

Passing unit tests validates the tested scenarios, but does not guarantee detection of every attack pattern or log format.

## Limitations

- **Per-IP detection:** Attempts distributed across many source IP addresses are not correlated as a single campaign.
- **Slow guessing:** Attempts spread over longer periods may remain LOW because the primary burst detector uses a short sliding window.
- **Log-format differences:** Authentication log formats vary by distribution, OpenSSH version, and logging configuration.
- **Traditional syslog timestamps:** These do not include a timezone and are interpreted using the machine's local timezone assumption. Mixing logs from different systems may require additional normalization.
- **Timestamp validation:** Additional testing against real-world log formats, timezone edge cases, and malformed input is still valuable.
- **No threat-intelligence enrichment:** GeoIP and reputation lookups are not currently implemented.
- **No automatic blocking:** SSH Sentinel generates alerts but does not itself block source IP addresses.
- **No measured detection benchmark yet:** Precision, recall, false-positive rates, and performance on large datasets have not yet been established.

## Future Improvements

- Detect password spraying and distributed brute-force activity.
- Add a longer time window for slow authentication attacks.
- Expand timestamp and log-format compatibility testing.
- Evaluate detection quality using labelled datasets and report precision, recall, and false-positive rates.
- Improve alert context and evidence presentation.
- Add optional integrations with SIEM and SOAR platforms.
- Improve automated regression testing with larger synthetic attack scenarios.

## Related Project: Wazuh + n8n Security Automation

SSH Sentinel is a standalone detection-engineering project.

Separately, I built a Wazuh and n8n security automation workflow that connects SSH brute-force alerts to a token-protected webhook, uses Gemini for AI-assisted alert analysis, sends email notifications for high/critical alerts, and triggers a firewall response through the Wazuh API.

The two projects demonstrate complementary skills:

- **SSH Sentinel:** Python development, log analysis, detection logic, event correlation, and testing.
- **Wazuh + n8n:** SIEM integration, AI-assisted triage, workflow automation, alert notification, and defensive response.

They are separate projects and are not currently integrated into a single pipeline.

## What I Learned

- Brute-force detection should consider the rate of failed attempts, not only the total count.
- Correlating failed authentication events with a subsequent successful login can highlight activity that a simple counter might miss.
- Duplicate log events need careful handling to avoid inflating attack counts.
- Timestamp normalization matters when events from different timezones are compared.
- Separating detection logic from the GUI makes software easier to test and maintain.
- Security automation requires validation, reliable logging, and safeguards against false positives.

## Author

**Baibhav Pradhan**  
Ethical Hacking & Cybersecurity Student | Defensive Security | SOC / Blue Team

- GitHub: [@pradhan77](https://github.com/pradhan77)
- LinkedIn: [Baibhav Pradhan](https://www.linkedin.com/in/baibhav-pradhan-1835b6399/)

---

*Built as a hands-on defensive cybersecurity project for learning, experimentation, and portfolio development.*

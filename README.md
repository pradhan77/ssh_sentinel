# SSH Sentinel

**A Python-based SSH brute-force detection tool for defensive security monitoring.**

SSH Sentinel analyzes OpenSSH authentication logs to identify suspicious login activity, classify brute-force attempts by severity, and detect potentially compromised accounts when a successful login follows repeated failures from the same IP address.

The project includes a command-line interface (CLI), a Tkinter graphical user interface (GUI), JSON output, and a unit-tested detection engine.

## Features

- **Sliding-window detection:** Identifies bursts of failed SSH authentication attempts within a configurable time window.
- **Severity classification:** Assigns LOW, MEDIUM, HIGH, or CRITICAL severity based on observed activity and login correlation.
- **Success-after-failure correlation:** Raises a CRITICAL alert when a successful login follows a sufficient number of failed attempts from the same IP address within the configured lookback period.
- **Duplicate-event handling:** Avoids double-counting certain PAM authentication failures that correspond to failed-password events from the same SSH process.
- **IPv4 and IPv6 support:** Parses source IP addresses and classifies addresses using Python's `ipaddress` module.
- **Timestamp parsing:** Supports ISO-style timestamps and traditional syslog timestamps, including timezone-offset handling for ISO timestamps.
- **CLI and JSON output:** Analyzes log files or system journal entries and produces structured output.
- **Tkinter GUI:** Provides a visual interface for reviewing alerts, filtering by severity, and monitoring logs.
- **Testable architecture:** Separates the analysis engine from the GUI so detection logic can be tested independently.

## How It Works

SSH Sentinel follows this workflow:

1. Reads SSH authentication logs from a file or the system journal.
2. Parses relevant authentication events, including failed attempts and accepted logins.
3. Groups failed authentication attempts by source IP address.
4. Calculates the peak number of failures within a sliding time window.
5. Assigns severity based on the configured detection thresholds.
6. Correlates successful logins with preceding failures from the same IP address.
7. Produces readable alerts or JSON output for further analysis.

## Detection Logic

The documented default severity thresholds are:

| Severity | Condition |
|---|---|
| LOW | Failed attempts from one IP with a peak below 3 in a 60-second window |
| MEDIUM | At least 3 failures from one IP in a 60-second window |
| HIGH | At least 5 failures from one IP in a 60-second window |
| CRITICAL | A successful login from an IP with at least 5 preceding failures within the previous 15 minutes |

A CRITICAL correlation alert takes precedence over the ordinary brute-force alert for the same source IP.

These thresholds are intended to help prioritize suspicious activity. They are not proof that an attack or account compromise has occurred. Legitimate users who repeatedly enter an incorrect password can also generate alerts.

## Requirements

- Python 3
- Linux recommended for live SSH log monitoring
- Tkinter for the graphical interface
- `journalctl` for reading system journal entries

On Kali Linux or Debian, install the required system packages:

```bash
sudo apt update
sudo apt install python3-tk
```

Live journal monitoring requires appropriate permissions to read the system journal. Depending on the distribution, this may involve membership in the `systemd-journal` or `adm` group.

## Installation

Clone the repository:

```bash
git clone https://github.com/pradhan77/ssh_sentinel.git
cd ssh_sentinel
```

Run the unit tests to verify the installation:

```bash
python3 -m unittest -v
```

The current test suite contains 31 unit tests covering parsing, detection thresholds, severity classification, IP handling, event deduplication, successful-login correlation, timestamp handling, and JSON serialization.

## Usage

### 1. Analyze a sample log file

```bash
python3 analyzer.py sample_logs/auth_sample.log
```

This analyzes the included sample authentication logs and displays detected activity.

### 2. Analyze an authentication log file

On systems that maintain an authentication log at `/var/log/auth.log`:

```bash
python3 analyzer.py /var/log/auth.log
```

The correct log path depends on the operating system and logging configuration. Some systems store authentication events only in the system journal.

### 3. Read the system journal

```bash
python3 analyzer.py --journal
```

Use this option on systems where SSH authentication events are available through `journalctl`.

### 4. Generate JSON output

```bash
python3 analyzer.py sample_logs/auth_sample.log --json
```

JSON output is useful for structured processing, testing, and potential future integration with SIEM or SOAR workflows.

### 5. Configure the detection threshold

For example, use a 30-second window and a threshold of 3 failures:

```bash
python3 analyzer.py auth.log --window 30 --threshold 3 --year 2026
```

The `--year` option applies to traditional syslog timestamps that do not contain a year. Check the CLI options supported by your installed version before using optional arguments.

### 6. Launch the graphical interface

```bash
python3 ssh_sentinel.py
```

The GUI provides a visual way to inspect alerts, filter by severity, and monitor authentication activity.

## Example Alert

The following is an illustrative example using synthetic log data and a documentation-only IP address:

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

This example represents repeated authentication failures followed by a successful login from the same source IP address. Such activity warrants investigation, but the alert alone does not prove that the account was compromised.

The included sample logs also demonstrate slower guessing attempts and IPv6 activity.

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
| `README.md` | Project documentation and usage instructions |

## Testing

Run the complete test suite:

```bash
python3 -m unittest -v
```

The current suite contains 31 tests covering:

- Empty input and irrelevant log entries
- Timestamp parsing and invalid dates
- Failed-password and PAM event handling
- IPv4 and IPv6 source addresses
- Severity thresholds and sliding-window behavior
- Successful-login correlation
- JSON serialization

Passing these tests validates the scenarios covered by the suite. It does not guarantee detection of every attack pattern, compatibility with every log format, or the absence of false positives.

## Limitations

- **Per-IP detection:** Attempts distributed across multiple source IP addresses are not correlated as a single campaign.
- **Slow guessing:** Attempts spread across longer periods may remain LOW because the primary burst detector uses a short sliding window.
- **Log-format differences:** Authentication log formats vary by distribution, OpenSSH version, and logging configuration.
- **Traditional syslog timestamps:** These timestamps do not contain a timezone. Their interpretation depends on the implementation's timezone handling, so mixed-system logs may require additional normalization.
- **Timestamp edge cases:** Testing against additional real-world log formats, timezone boundaries, and malformed input would strengthen reliability.
- **No threat-intelligence enrichment:** GeoIP and IP reputation lookups are not currently implemented.
- **No automatic blocking:** SSH Sentinel generates alerts but does not itself block source IP addresses.
- **No measured detection benchmark:** Precision, recall, false-positive rates, and performance on large datasets have not yet been established.

## Future Improvements

- Detect password spraying and distributed brute-force activity.
- Add longer detection windows for slow authentication attacks.
- Expand timestamp and log-format compatibility testing.
- Evaluate detection quality using labelled datasets and report precision, recall, and false-positive rates.
- Improve alert context and evidence presentation.
- Add optional SIEM and SOAR integrations.
- Expand automated regression testing with larger synthetic attack scenarios.

## Related Project: Wazuh + n8n Security Automation

SSH Sentinel is a standalone detection-engineering project.

Separately, I built a Wazuh and n8n security automation workflow that connects SSH brute-force alerts to a token-protected webhook, uses Gemini for AI-assisted alert analysis, sends email notifications for high/critical alerts, and triggers a firewall response through the Wazuh API.

These projects demonstrate complementary skills:

- **SSH Sentinel:** Python development, log analysis, detection logic, event correlation, and unit testing.
- **Wazuh + n8n:** SIEM integration, AI-assisted triage, workflow automation, alert notification, and defensive response.

The two projects are separate and are not currently integrated into a single pipeline.

## What I Learned

- Brute-force detection should consider the rate of failed attempts, not only the total count.
- Correlating failed authentication events with a subsequent successful login can reveal activity that a simple counter might miss.
- Duplicate log events require careful handling to avoid inflating attack counts.
- Timestamp normalization matters when comparing events from different timezones.
- Separating detection logic from the GUI makes software easier to test and maintain.
- Security automation requires validation, reliable logging, and safeguards against false positives.

## Author

**Baibhav Pradhan**

Ethical Hacking & Cybersecurity Student | Defensive Security | SOC / Blue Team

- GitHub: [@pradhan77](https://github.com/pradhan77)
- LinkedIn: [Baibhav Pradhan](https://www.linkedin.com/in/baibhav-pradhan-

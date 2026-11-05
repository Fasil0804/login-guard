# Login Guard

A small Python tool that reads login logs and flags repeated failed attempts from the same IP address. Built as an AI-assisted cybersecurity learning project maintained by [Fasil Mohamed](https://github.com/Fasil0804).

**Example:** if one IP produces five failed logins within five minutes, Login Guard adds it to a report for review.

## What it does

- Reads a CSV file of login events.
- Counts successful logins, failed logins, users and IP addresses.
- Detects bursts of failures using a configurable rolling time window.
- Reports one peak window per flagged IP, including affected usernames.
- Accepts IPv4 and IPv6 addresses and timezone-aware timestamps.
- Reports invalid rows and excludes them from the analysis.
- Prints a readable report or JSON for another tool to consume.

No API keys, account access, network requests or third-party Python packages are required. The program reads the file you choose and prints a report; it does not modify that file.

## Quick start

Use **Python 3.11 or later**. Download and extract the repository, open a terminal in its folder, then run:

```bash
python login_guard.py samples/login_events.csv
```

On Windows, use `py` instead of `python` if needed. On macOS or Linux, use `python3` if that is how Python is installed.

The included sample contains invented events and documentation IP addresses. Its report includes:

```text
Valid events: 12
Successful logins: 4
Failed logins: 8
Unique IPs: 4 | Unique users: 4
Invalid rows skipped: 0
```

It flags `203.0.113.10` for **5 failed logins** between `09:01:00` and `09:04:00` UTC. The later successful login does not erase the failures.

### Change the rule

```bash
python login_guard.py samples/login_events.csv --threshold 3 --window-minutes 10
```

This looks for at least three failures from one IP within ten minutes. Threshold must be an integer of at least 2. The window must be an integer from 1 to 10080 minutes (seven days).

### Export JSON

```bash
python login_guard.py samples/login_events.csv --json
python login_guard.py samples/login_events.csv --json > report.json
```

The second command uses your shell to save the output. Pick a new output filename; shell redirection can overwrite an existing file. JSON includes `summary`, `settings`, `alerts` and `invalid_rows`.

## CSV format

The file must have exactly these four headers; their order can vary:

| Column | Example | Meaning |
| --- | --- | --- |
| `timestamp` | `2026-11-01T09:00:00Z` | ISO 8601 time including a timezone; `+08:00` also works |
| `username` | `admin` | Non-empty account name |
| `source_ip` | `203.0.113.10` | A valid IPv4 or IPv6 address |
| `status` | `failure` | `success` or `failure`, ignoring letter case |

```csv
timestamp,username,source_ip,status
2026-11-01T09:00:00Z,admin,203.0.113.10,failure
2026-11-01T09:01:00Z,admin,203.0.113.10,failure
2026-11-01T09:02:00Z,admin,203.0.113.10,failure
2026-11-01T09:03:00Z,admin,203.0.113.10,failure
2026-11-01T09:04:00Z,admin,203.0.113.10,failure
```

Rows do not need to be in time order. Times are converted to UTC before sorting. Failures exactly five minutes apart count within a five-minute window. Successful logins contribute to totals but neither count as failures nor reset the rule.

A malformed record is skipped with its CSV line number and reason. Missing/duplicate headers, broken CSV quoting, unreadable files and invalid command-line settings stop the program with exit code 2. A completed report returns exit code 0, including when there are alerts or skipped rows. A headers-only file produces a zero-event report.

## How the detection works

1. Validate events and sort their timestamps.
2. Keep a separate queue of recent failed events for each IP.
3. Remove events older than the chosen window.
4. Flag the IP when its queue reaches the threshold.
5. Keep the largest matching window for each IP. For equal peaks, keep the first.

An alert's start and end are the first and last failures in that peak window. Its usernames describe that window rather than all activity from the IP.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests cover the sample report, inclusive time boundaries, expired events, timezone conversion, midnight, unordered input, separate IPs, IPv6 normalization, invalid records, successful logins, peak windows and CLI errors. A GitHub Actions workflow is included to run them on Python 3.11, 3.12 and 3.13 when pushed.

## Learn the code

| Part | Purpose |
| --- | --- |
| `read_events()` | Reads the CSV and validates each event |
| `analyse()` | Counts events and finds failed-login bursts |
| `text_report()` | Turns the result into a readable summary |
| `main()` | Reads terminal options and runs the analysis |

Try lowering the sample threshold to 2, increasing the window to 10 minutes, and comparing the result. Then add invented events and explain why an IP does or does not match. The [learning guide](docs/LEARNING_GUIDE.md) walks through this.

## Limitations

This is a small offline learning tool, not a production monitoring system. It expects this CSV format rather than raw SSH, Windows or cloud logs. It reads the file into memory. It does not block IPs, collect logs, identify compromised accounts or detect attempts spread across many IPs.

A shared IP or mistyped passwords can trigger an alert. An alert is a reason to review the events, not proof of an attack. Use invented logs when sharing examples; keep real account and network information out of the public repository.

## Contributions

Bug reports and small improvements are welcome. Include a minimal example with invented events, explain the expected result, and run the tests before proposing a change. Potential next steps include a separate parser for a documented real-world log format and an optional per-account detection rule.

## License and acknowledgements

[MIT License](LICENSE). Initial code, sample data, tests and documentation were created with AI assistance. This repository is a learning project; no claims of production use, external adoption or independent security review are made.

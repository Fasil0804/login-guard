#!/usr/bin/env python3
"""Find bursts of failed logins in a CSV file using only Python's standard library."""

import argparse
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import sys


FIELDS = ("timestamp", "username", "source_ip", "status")


def read_events(path):
    """Return valid events and row errors; invalid records never affect counts."""
    events, errors = [], []
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle, strict=True)
        if reader.fieldnames is None or len(reader.fieldnames) != len(FIELDS) or set(reader.fieldnames) != set(FIELDS):
            raise ValueError("CSV headers must be timestamp,username,source_ip,status (in any order).")
        for row in reader:
            try:
                if None in row or any(row[field] is None for field in FIELDS):
                    raise ValueError("incorrect number of columns")
                timestamp = datetime.fromisoformat(row["timestamp"].strip())
                if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                    raise ValueError("timestamp must include a timezone, such as Z or +08:00")
                username = row["username"].strip()
                if not username:
                    raise ValueError("username must not be empty")
                source_ip = str(ipaddress.ip_address(row["source_ip"].strip()))
                status = row["status"].strip().lower()
                if status not in ("success", "failure"):
                    raise ValueError("status must be success or failure")
                events.append({"timestamp": timestamp.astimezone(timezone.utc), "username": username,
                               "source_ip": source_ip, "status": status})
            except ValueError as error:
                errors.append({"line": reader.line_num, "reason": str(error)})
    events.sort(key=lambda event: event["timestamp"])
    return events, errors


def analyse(events, errors, threshold=5, window_minutes=5):
    """Report one peak failed-login window per IP, counting both window boundaries."""
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 2:
        raise ValueError("threshold must be an integer of at least 2")
    if not isinstance(window_minutes, int) or isinstance(window_minutes, bool) or not 1 <= window_minutes <= 10080:
        raise ValueError("window minutes must be an integer between 1 and 10080")
    window = timedelta(minutes=window_minutes)
    queues = defaultdict(deque)
    peaks = {}
    # Sort here as well so callers of this function can pass unordered events.
    for event in sorted(events, key=lambda item: item["timestamp"]):
        if event["status"] != "failure":
            continue
        queue = queues[event["source_ip"]]
        while queue and event["timestamp"] - queue[0]["timestamp"] > window:
            queue.popleft()
        queue.append(event)
        previous = peaks.get(event["source_ip"])
        if len(queue) >= threshold and (previous is None or len(queue) > previous["failed_attempts"]):
            peaks[event["source_ip"]] = {
                "source_ip": event["source_ip"],
                "failed_attempts": len(queue),
                "usernames": sorted({item["username"] for item in queue}),
                "window_start": queue[0]["timestamp"].isoformat(),
                "window_end": event["timestamp"].isoformat(),
            }
    failures = sum(event["status"] == "failure" for event in events)
    return {
        "summary": {"valid_events": len(events), "successful_logins": len(events) - failures,
                    "failed_logins": failures, "unique_ips": len({event["source_ip"] for event in events}),
                    "unique_users": len({event["username"] for event in events}), "invalid_rows": len(errors)},
        "settings": {"threshold": threshold, "window_minutes": window_minutes},
        "alerts": sorted(peaks.values(), key=lambda item: (-item["failed_attempts"], item["source_ip"])),
        "invalid_rows": errors,
    }


def text_report(report):
    summary = report["summary"]
    settings = report["settings"]
    lines = ["LOGIN GUARD", "===========",
             f"Valid events: {summary['valid_events']}",
             f"Successful logins: {summary['successful_logins']}",
             f"Failed logins: {summary['failed_logins']}",
             f"Unique IPs: {summary['unique_ips']} | Unique users: {summary['unique_users']}",
             f"Invalid rows skipped: {summary['invalid_rows']}", "",
             f"Rule: at least {settings['threshold']} failures from one IP within {settings['window_minutes']} minute(s).",
             "Both ends of the time window are included. All displayed times are UTC.", ""]
    if not report["alerts"]:
        lines.append("No IP addresses met this rule.")
    for alert in report["alerts"]:
        lines.extend([f"REVIEW {alert['source_ip']}: {alert['failed_attempts']} failed logins in its peak window",
                      f"  Users: {', '.join(alert['usernames'])}",
                      f"  From: {alert['window_start']}", f"  To:   {alert['window_end']}"])
    if report["invalid_rows"]:
        lines.append("\nSkipped rows:")
        lines.extend(f"  Line {item['line']}: {item['reason']}" for item in report["invalid_rows"])
    lines.extend(["", "A match is a review signal; it does not prove an attack."])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path, help="CSV with timestamp,username,source_ip,status columns")
    parser.add_argument("--threshold", type=int, default=5, help="minimum failures per IP (default: 5; minimum: 2)")
    parser.add_argument("--window-minutes", type=int, default=5, help="rolling window from 1 to 10080 minutes (default: 5)")
    parser.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    args = parser.parse_args(argv)
    try:
        events, errors = read_events(args.csv_file)
        report = analyse(events, errors, args.threshold, args.window_minutes)
    except (OSError, UnicodeError, ValueError, csv.Error) as error:
        parser.exit(2, f"Error: {error}\n")
    print(json.dumps(report, indent=2) if args.json else text_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())

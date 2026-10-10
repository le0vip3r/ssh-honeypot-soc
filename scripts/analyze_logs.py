#!/usr/bin/env python3
"""Analyze Cowrie JSON events for a local SSH honeypot lab."""

import json
from collections import Counter
from pathlib import Path

import sys
LOG_FILE = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else Path.home() / "ssh-honeypot/var/log/cowrie/cowrie.json"
FAILED_LOGIN_ALERT_THRESHOLD = 5


def load_events(path):
    events = []
    malformed = 0

    with path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                malformed += 1
                print(f"[WARNING] Invalid JSON at line {line_number}")

    return events, malformed


def main():
    if not LOG_FILE.is_file():
        print(f"[ERROR] Log file not found: {LOG_FILE}")
        return

    events, malformed = load_events(LOG_FILE)

    event_types = Counter(
        event.get("eventid", "unknown") for event in events
    )
    sessions = {
        event["session"]
        for event in events
        if event.get("session")
    }

    failed_events = [
        event for event in events
        if event.get("eventid") == "cowrie.login.failed"
    ]
    successful_events = [
        event for event in events
        if event.get("eventid") == "cowrie.login.success"
    ]
    command_events = [
        event for event in events
        if event.get("eventid") == "cowrie.command.input"
    ]

    usernames = Counter(
        event.get("username", "unknown")
        for event in failed_events
    )

    commands = Counter(
        event.get("input", "").strip()
        for event in command_events
        if event.get("input", "").strip()
    )

    print("=" * 52)
    print("         COWRIE SSH HONEYPOT ANALYZER")
    print("=" * 52)
    print(f"Log file:              {LOG_FILE}")
    print(f"Total events:          {len(events)}")
    print(f"Malformed JSON lines:  {malformed}")
    print(f"Unique sessions:       {len(sessions)}")
    print(f"Failed login events:   {len(failed_events)}")
    print(f"Successful logins:     {len(successful_events)}")
    print(f"Commands recorded:     {len(command_events)}")

    print("\n[EVENT TYPES]")
    for event_type, count in event_types.most_common():
        print(f"{event_type:<32} {count}")

    print("\n[TOP USERNAMES IN FAILED LOGINS]")
    if usernames:
        for username, count in usernames.most_common(10):
            print(f"{username:<24} {count}")
    else:
        print("No failed login events recorded.")

    print("\n[RECORDED COMMANDS]")
    if commands:
        for command, count in commands.most_common(15):
            print(f"{command:<32} {count}")
    else:
        print("No commands recorded.")

    print("\n[DETECTION ALERTS]")
    failed_by_source = Counter(
        event.get("src_ip", "unknown")
        for event in failed_events
    )

    alerts = 0
    for source, count in failed_by_source.items():
        if count >= FAILED_LOGIN_ALERT_THRESHOLD:
            alerts += 1
            print(
                f"[ALERT] {count} failed logins from source {source}"
            )

    if alerts == 0:
        print("No repeated-failed-login threshold reached.")

    print("\nAnalysis complete.")


if __name__ == "__main__":
    main()


#!/usr/bin/env python3
import json
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

THRESHOLD = 5
WINDOW_SECONDS = 300


def process_event(event, attempts, alerted):
    if event.get("eventid") != "cowrie.login.failed":
        return

    source = event.get("src_ip", "unknown")
    if source == "unknown":
        return

    now = time.monotonic()
    q = attempts[source]
    q.append(now)

    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()

    count = len(q)
    print(f"[EVENT] Failed login from {source} ({count}/{THRESHOLD})",
          flush=True)

    
    if count >= THRESHOLD and source not in alerted:
        timestamp = time.strftime(
            "%Y-%m-%d %H:%M:%S %z", time.localtime()
        )
        message = (
            f"[ALERT] {count} failed logins from {source} "
            f"within 5 minutes!"
        )
        print(message, flush=True)

        log_path = Path.home() / "ssh-honeypot/var/alerts/alerts.log"
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"{timestamp} {message}\n")

        alerted.add(source)


def test_mode():
    print("SELF-TEST MODE — synthetic events only.")
    attempts = defaultdict(deque)
    alerted = set()

    for _ in range(5):
        event = {
            "eventid": "cowrie.login.failed",
            "src_ip": "192.0.2.10",
        }
        process_event(event, attempts, alerted)

    print("Self-test complete.")


def live_mode():
    import subprocess

    follower = r'''
import os, time
p = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
with open(p, encoding="utf-8") as f:
    f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if line:
            print(line, end="", flush=True)
        else:
            time.sleep(0.2)
'''
    cmd = [
        "sudo", "docker", "exec", "-i", "cowrie-honeypot",
        "/cowrie/cowrie-env/bin/python3", "-u", "-c", follower
    ]

    print("Watching live Cowrie events. Press Ctrl+C to stop.")
    attempts = defaultdict(deque)
    alerted = set()

    with subprocess.Popen(
        cmd, stdout=subprocess.PIPE, text=True, bufsize=1
    ) as proc:
        for line in proc.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            process_event(event, attempts, alerted)


if __name__ == "__main__":
    try:
        if "--self-test" in sys.argv:
            test_mode()
        else:
            live_mode()
    except KeyboardInterrupt:
        print("\nDetector stopped.")

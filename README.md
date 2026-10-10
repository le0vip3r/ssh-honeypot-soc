# SSH Honeypot SOC

A hands-on cybersecurity lab that uses **Cowrie SSH Honeypot**, Python-based failed-login detection, and a Flask dashboard to observe and analyze SSH authentication activity.

## Features

- **SSH honeypot:** Cowrie records SSH interactions in a controlled lab environment.
- **Live detection:** Monitors new Cowrie events and alerts when a source records five failed logins within five minutes.
- **Log analysis:** Python script for analyzing recorded honeypot events.
- **SOC dashboard:** Displays authentication activity, source IPs, recent events, and generated alerts.
- **Synthetic testing:** Includes sample failed-login events to test detection logic without relying on real attacks.

## Architecture

```text
SSH Client / Test Traffic
          |
          v
   Cowrie Honeypot
          |
          v
      JSON Events
          |
          v
 Python Live Detector -----> Alert Log
          |
          v
    Flask Dashboard
```

## Technology Stack

- Kali Linux
- Docker
- Cowrie SSH Honeypot
- Python 3
- Flask
- JSON event logs
- Git and GitHub

## Project Structure

```text
ssh-honeypot/
├── dashboard/
│   └── app.py
├── scripts/
│   ├── analyze_logs.py
│   ├── live_detector.py
│   └── test_failed_logins.json
├── var/                 # Local runtime data; not committed
├── .gitignore
└── README.md
```

## Detection Logic

The live detector monitors Cowrie's JSON event stream and tracks failed SSH logins by source IP. It raises an alert when a source reaches **five failed logins within a rolling five-minute window**.

The threshold is configurable in the detector script.

## Running the Lab

### Prerequisites

- Kali Linux
- Docker, with the `cowrie-honeypot` container configured and running
- Python 3 and Flask

### 1. Start the live detector

From the project directory, run:

```bash
python3 ~/ssh-honeypot/scripts/live_detector.py
```

The detector monitors new Cowrie events and writes threshold alerts to `~/ssh-honeypot/var/alerts/alerts.log`.

### 2. Start the dashboard

Open a separate terminal and run:

```bash
cd ~/ssh-honeypot/dashboard
python3 app.py
```

Open `http://127.0.0.1:5000` in your browser on the Kali machine.

### 3. Analyze recorded events

To analyze a local copy of the Cowrie log, copy it from the container:

```bash
sudo docker cp cowrie-honeypot:/cowrie/cowrie-git/var/log/cowrie/cowrie.json ~/ssh-honeypot/var/log/cowrie/cowrie.json
```

Then run:

```bash
python3 ~/ssh-honeypot/scripts/analyze_logs.py
```

The Cowrie container must be running for the copy command to work. These commands assume the existing lab configuration; a fresh installation may require additional setup.
## Safety and Scope

This project is intended for authorized, controlled security testing. Keep the honeypot isolated and do not expose it to the public internet without appropriate network isolation, monitoring, and security controls.

Sample events use reserved documentation IP addresses. Local Docker traffic and synthetic events are test data, not evidence of genuine external attacks.

## Current Status

- [x] Cowrie honeypot configured
- [x] Python failed-login detector implemented
- [x] Alert logging implemented
- [x] Flask dashboard implemented
- [x] Synthetic detector test included
- [ ] Setup documentation and screenshots to be expanded

## Disclaimer

This project is for educational and defensive cybersecurity research. Only use it on systems and networks you own or are authorized to test.

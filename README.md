# 🔍 Automated Network Security Scanner

A Python-based network monitoring tool that scans for connected devices, identifies them, assigns risk scores, detects new devices, and sends email alerts.

## Features
- Scans entire home network using Nmap
- Identifies device types (iPhone, printer, router, etc.)
- Assigns risk scores based on open ports
- Generates a color-coded HTML security report
- Emails alerts when new devices are detected
- Tracks how many times each device has been seen
- Only runs on home network (will not scan unknown networks)
- Logs scan history over time

## Tools & Technologies
- Python 3
- Nmap / python-nmap
- SMTP / Gmail API for alerts
- HTML report generation
- launchd for scheduling (Mac)

## How It Works
1. `scanner.py` — Full scan with CVE lookup and HTML report
2. `alerts.py` — Lightweight scan that emails alerts on new devices
3. `schedule.py` — Runs automatically once per day at 9AM

## Production Notes
In a real enterprise environment this would be configured to:
- Run every hour instead of once daily
- Monitor multiple subnets simultaneously
- Feed alerts into a SIEM like Splunk
- Correlate new device alerts with threat intelligence feeds
- Log all events to a centralized logging server

## Security & Legal
This tool is designed for use on your own network only.
Scanning networks you do not own is illegal without explicit permission.
The home network check ensures the tool only runs on the configured network.

## Example Output
- 15 devices discovered
- 1 high risk (network printer — ports 515, 9100 exposed)
- 1 medium risk (unknown device with remote access ports)
- Email alert sent with device inventory and new device flags

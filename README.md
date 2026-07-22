# Network Service Monitor

A desktop application for real-time network connection monitoring, designed exclusively for Windows.

## Features
- Displays TCP/UDP connections in real time
- Shows PID, process name, service name, command line, path, creation time, and user
- Security analysis fields: internal/external network determination, reverse DNS, risk score, and common service identification
- Terminate, pause, or resume processes
- Block or unblock corresponding processes using the Windows Firewall
- Add local notes and tags to each connection
- Search, filter, sort, and refresh in real time

## System Requirements
- Windows 10 / 11
- Python 3.13+
- Administrator privileges: Blocking / unblocking / terminating / pausing / resuming require elevated privileges

## Installation
```bash
pip install -r requirements.txt
python -m network_monitor
```

## Notes
- This is a desktop visualization and management tool; it does not bypass Windows security restrictions.
- “Toggle Connection” primarily relies on Windows firewall rules and process control.
- Reverse DNS, external ratings, and geolocation are optional features; the tool functions normally even when offline.

## Project Structure
- `src/network_monitor/ui`: User interface
- `src/network_monitor/core`: Scanning, control, and analysis
- `src/network_monitor/storage`: SQLite notes and tags
- `src/network_monitor/utils`: Formatting tools

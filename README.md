# Secure File Transfer Monitor & DLP

A lightweight, real-time Data Loss Prevention (DLP) system designed to monitor filesystem activities, inspect file integrity, track whitelisted processes, and detect unauthorized exfiltration to removable USB media.

The system uses a multi-threaded architecture with a FastAPI backend, a React-based frontend dashboard, and a local SQLite database for audit trails.

---

## Architecture Overview

```
                        [ Local Filesystem Events ]
                                     │
                                     ▼ (Watchdog)
  [ USB Devices ] ──► [ DLP Rules Policy Engine ] ──► [ SQLite DB (audit.db) ]
    (Psutil loop)                    │
                                     ▼ (WebSockets)
                              [ React App ]
```

- **Backend**: FastAPI ASGI server, sqlite3, `watchdog` (for filesystem directory event hooking), and `psutil` (polling for removable drive mounts).
- **Frontend**: Vite + React, Chart.js (via `react-chartjs-2`), and WebSockets for real-time log streaming.
- **Database**: SQLite3 (`audit.db`) storing raw logs (`file_events`), policy triggers (`alerts`), and runtime rules (`settings`).

---

## DLP Detection Policies

The engine runs incoming filesystem and hardware metadata against five core policy rules:

1. **USB Exfiltration Detection** (*Critical*): Alerts if a file flagged as sensitive is created, modified, or moved into any path designated as a removable USB storage directory.
2. **Sensitive Path Relocation** (*Medium*): Detects when a restricted file is moved out of protected directories to an unmonitored or public directory.
3. **Process Whitelisting** (*High*): Restricts access to sensitive documents. Any unwhitelisted executable (e.g. scripts, unauthorized binaries) that writes to sensitive files will trigger an alert.
4. **Integrity Validation** (*High/Low*): Stores SHA256 hashes of files. If a file is modified and its computed hash mismatches its previous state in the audit database, it flags a tamper alert.
5. **Bulk Transfer Burst** (*High*): Tracks transaction frequency. If file events exceed the configured threshold (e.g., 10 events) within a short window (e.g., 5 seconds), it flags a bulk transfer threat.

---

## System Requirements

- **Python**: 3.9 or higher
- **Node.js**: 18.x or higher
- **OS**: Windows (tested for command shell execution and disk partition monitoring)

---

## Getting Started

### 1. Automated Launcher (Windows)
Double-click `run.bat` or run it from a PowerShell/CMD terminal in the root directory:
```cmd
.\run.bat
```
This launcher installs python dependencies, initializes the database schema, starts the FastAPI server, and launches the React development server.

### 2. Manual Setup
If you want to start backend and frontend services separately:

**Backend API:**
```bash
cd backend
pip install -r requirements.txt
python db.py     # Setup database
python main.py   # Run FastAPI on http://127.0.0.1:8000
```

**Frontend Dashboard:**
```bash
cd frontend
npm install
npm run dev      # Run Vite on http://localhost:5173
```

---

## Interactive Simulation & Testing

You can verify and test the policy engine using two methods:

### 1. Automated Script
Run the verification script to run simulated file operations in the sandbox folder and query the local SQLite logs:
```bash
python verify_monitor.py
```

### 2. UI Threat Simulator
The frontend dashboard includes a **Threat Simulator** panel. Click the simulation buttons to trigger:
- **Plug USB**: Simulates a drive insertion event.
- **Malicious Code**: Writes fake malware payload files using an unapproved process signature.
- **Exfiltrate USB**: Automatically copies sensitive financials into simulated USB directories.
- **Bulk Burst**: Fast-writes 12 temp files in under 2 seconds to verify the frequency alarm.
- **Tamper File**: Modifies CSV datasets to trigger SHA256 mismatch alerts.

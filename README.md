# 🛡️ CyberShield

CyberShield is an educational Python dashboard for exploring login records and flagging repeated failed-login patterns. It uses Streamlit for the interface and Pandas for data processing.

## Features
- Login success/failure metrics
- Rule-based suspicious-IP flagging by failed-login count
- Date-range and status filters
- Charts for status, IP addresses, and activity over time
- Search by username or IP address
- CSV upload and filtered CSV report download
- Synthetic demonstration records included

## Project files
- `app.py` — Streamlit dashboard
- `requirements.txt` — Python dependencies
- `sample_logins.csv` — example data for testing upload
- `.gitignore` — ignores Python cache and virtual environment files
- `LICENSE` — MIT License
- `.streamlit/config.toml` — theme configuration
- `tests/test_detection.py` — basic tests for detection logic

## Run locally
Use Python 3.10 or newer. In a terminal, from this folder:

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## CSV format
CSV uploads must include these columns: `timestamp`, `username`, `ip_address`, and `status`.

Accepted status labels include `Success`, `Successful`, `login_success`, `Failed`, `Failure`, and `login_failed` (case-insensitive).

Example:

```csv
timestamp,username,ip_address,status
2026-10-20 08:15:00,admin,192.168.1.10,Success
2026-10-20 08:17:00,admin,192.168.1.10,Failed
```

## Detection logic
An IP is flagged when it has at least the configured number of failed login records within the selected date range. Detection is calculated before the display-status filter so choosing to display only successful logins does not hide a flagged IP. This simple heuristic is not proof of malicious activity.

## Limitations
The sample records are synthetic and are not live network events. The dashboard does not collect operating-system logs or perform live network monitoring. Treat flags as prompts for investigation, not confirmed attacks.

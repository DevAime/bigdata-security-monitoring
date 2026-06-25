
# Big Data Access Log Security Platform

A security monitoring platform developed for a Big Data Security course project. The tool simulates a monitoring and auditing layer within a big data pipeline, covering log analysis, behavioral pattern visualization, and rule-based threat detection.

---

## Context

This project was built as part of a group assignment focused on security controls across the big data lifecycle. The platform addresses two components of the pipeline:

- **Log Analysis and Visualization** — understanding access patterns and surfacing anomalies
- **Security Monitoring** — applying rule-based detection to flag suspicious behavior

The dataset (`access_logs.csv`) simulates user access logs from a multi-role data environment with realistic normal and suspicious behavior injected.

---

## Features

- Upload CSV or Excel access log files
- Interactive analysis dashboard with filters by user, action, and dataset
- Hourly activity chart with working-hours boundary overlay
- User-action heatmap, location breakdown, device distribution
- Eight configurable detection rules with severity classification (LOW / MEDIUM / HIGH / CRITICAL)
- Flagged events table with color-coded severity and CSV export
- Consolidated report summary with monitoring recommendations
- Standalone rules script usable independently from the CLI

---

## Project Structure

```
access_logs.csv      Simulated access log dataset
app.py               Streamlit application (analysis dashboard + monitoring UI)
rules.py             Standalone detection engine (CLI usage)
requirements.txt     Python dependencies
```

---

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

**Requirements:** Python 3.9+, Streamlit, pandas, matplotlib, openpyxl

---

## Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| Off-hours access | Access before 08:00 or after 18:00 | MEDIUM |
| High request rate | More than 10 requests per user in 5 minutes | HIGH |
| Suspicious location | Location tagged as Foreign or Unknown | MEDIUM |
| Delete action | Any delete operation on any dataset | HIGH |
| Delete on sensitive dataset | Delete on finance, HR, or payroll data | CRITICAL |
| Failed access | Failed access attempt | LOW |
| Consecutive failures | 3 or more consecutive failures by one user | HIGH |
| Unknown device | Device type unidentifiable | LOW |
| Rapid location switch | Same user from two locations within 30 minutes | HIGH |
| Guest accessing sensitive data | Guest role accessing restricted datasets | HIGH |

---

## CLI Usage (rules.py)

```bash
# Run all rules
python rules.py access_logs.csv

# Run specific rules
python rules.py access_logs.csv --rules DELETE_ACTION HIGH_REQUEST_RATE OFF_HOURS_ACCESS

# Custom output path
python rules.py access_logs.csv --output flagged_report.csv
```

Produces `flagged_events.csv` and `monitoring_alerts.log`.

---

## Course

Big Data Security — DSA4030

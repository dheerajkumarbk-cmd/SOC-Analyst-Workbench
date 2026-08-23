SOC Analyst Workbench

This repository provides a self-contained simulated Security Operations Center (SOC) triage tool demonstrating the full analyst workflow: Detect → Correlate → Triage → Report.

Why this exists
- Correlation reduces false positives by grouping related alerts into incidents.
- Allowlist (suppression) demonstrates how known admin activity can be marked but not deleted to avoid hiding potentially important context.
- MTTD/MTTR metrics show detection and response timelines used to evaluate SOC performance.
- Seeded sample data allows a portfolio-ready demo without covering the dashboard with blank widgets before the data is present.

Files
- `generate_logs.py`: creates synthetic `logs.csv` including a clear multi-stage attack chain and allowlisted admin activity.
- `backend/scripts/seed_data.py`: creates a realistic 14-day SQLite dataset with a mix of alert types, incident groupings, risk levels, and investigation states.
- `detection_engine.py`: reads `logs.csv`, detects alerts (brute force T1110, port scan T1046, impossible travel T1078, privilege escalation T1068), suppresses allowlisted IPs, correlates alerts into incidents, writes `alerts.csv` and `incidents.json`.
- `report_generator.py`: generates markdown incident reports for multi-stage incidents.
- `app.py`: Streamlit dashboard to view incidents, change disposition, add analyst notes, and generate/download reports.
- `requirements.txt`: minimal dependencies.

How to run

1. Create a virtualenv and install requirements:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2. Seed the demo database with realistic sample SOC data:

```bash
make seed
```

or directly:

```bash
python backend/scripts/seed_data.py
```

3. Run the Streamlit app:

```bash
streamlit run app.py
```

Demo mode and default filters
- The dashboard defaults to a 14-day time window rather than a 1-hour view so seeded data is visible immediately.
- When the SQLite demo database is present, the app shows a Demo mode banner to clarify that the data is sample traffic, not live production telemetry.
- Empty states are displayed for charts, tables, logs preview, and risk views when there is genuinely zero data, preventing the dashboard from looking broken before seeding.

Design notes
- The allowlist is intentionally soft-suppressed: entries are marked as `suppressed: allowlisted admin IP` rather than removed so analysts can review and override.
- Correlation groups alerts by `source_ip` using a 30-minute rolling window to form incidents; this is intentionally simple to keep the demo focused on workflow rather than advanced threat intel.
- MTTD is computed as time between first malicious event and when detection occurred. MTTR is simulated for demo purposes.
- Seeded data includes 42 logs, multiple correlated incidents, alert risk spread across low/medium/high/critical, and a mix of in-progress and resolved cases for realistic workflow coverage.

License: MIT

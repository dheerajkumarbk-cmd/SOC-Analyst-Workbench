SOC Analyst Workbench

This repository provides a self-contained simulated Security Operations Center (SOC) triage tool demonstrating the full analyst workflow: Detect → Correlate → Triage → Report.

Why this exists
- Correlation reduces false positives by grouping related alerts into incidents.
- Allowlist (suppression) demonstrates how known admin activity can be marked but not deleted to avoid hiding potentially important context.
- MTTD/MTTR metrics show detection and response timelines used to evaluate SOC performance.

Files
- `generate_logs.py`: creates synthetic `logs.csv` including a clear multi-stage attack chain and allowlisted admin activity.
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

2. Generate logs, run detection, and generate initial reports:

```bash
python generate_logs.py
python detection_engine.py
python report_generator.py
```

3. Run the Streamlit app:

```bash
streamlit run app.py
```

Design notes
- The allowlist is intentionally soft-suppressed: entries are marked as `suppressed: allowlisted admin IP` rather than removed so analysts can review and override.
- Correlation groups alerts by `source_ip` using a 30-minute rolling window to form incidents; this is intentionally simple to keep the demo focused on workflow rather than advanced threat intel.
- MTTD is computed as time between first malicious event and when detection occurred. MTTR is simulated for demo purposes.

License: MIT

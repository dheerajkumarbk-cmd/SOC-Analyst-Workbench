import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from report_generator import generate_markdown

APP_ROOT = Path(__file__).resolve().parent
DB_PATH = APP_ROOT / "backend" / "data" / "soc_workbench.db"
LEGACY_LOGS = APP_ROOT / "logs.csv"
LEGACY_ALERTS = APP_ROOT / "alerts.csv"
LEGACY_INCIDENTS = APP_ROOT / "incidents.json"

st.set_page_config(layout="wide")


def render_empty_state(title: str, message: str, icon: str = "📭"):
    st.markdown(f"### {icon} {title}")
    st.caption(message)


@st.cache_data
def load_seeded_data():
    if not DB_PATH.exists():
        return pd.DataFrame(), pd.DataFrame(), []

    conn = sqlite3.connect(DB_PATH)
    try:
        logs = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp ASC", conn)
        alerts = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp ASC", conn)
        incidents = json.loads(
            pd.read_sql_query("SELECT * FROM incidents ORDER BY start_time ASC", conn).to_json(orient="records")
        )
    finally:
        conn.close()
    return logs, alerts, incidents


@st.cache_data
def load_legacy_data():
    logs = pd.read_csv(LEGACY_LOGS) if LEGACY_LOGS.exists() else pd.DataFrame(columns=["timestamp", "source_ip", "event_type"])
    alerts = pd.read_csv(LEGACY_ALERTS) if LEGACY_ALERTS.exists() else pd.DataFrame(columns=["timestamp", "source_ip", "alert_type", "severity"])
    incidents = json.loads(LEGACY_INCIDENTS.read_text()) if LEGACY_INCIDENTS.exists() else []
    return logs, alerts, incidents


@st.cache_data
def load_dashboard_data():
    if DB_PATH.exists():
        return load_seeded_data()
    return load_legacy_data()


def parse_timestamp_series(series: pd.Series) -> pd.Series:
    if series.empty:
        return pd.Series(dtype="datetime64[ns, UTC]")
    return pd.to_datetime(series, errors="coerce", utc=True)


st.title("SOC Analyst Workbench — Detect → Correlate → Triage → Report")

logs, alerts, incidents = load_dashboard_data()
seeded_data = DB_PATH.exists()
if seeded_data:
    st.info("Demo mode active: showing seeded sample data for walkthroughs. This is not production telemetry.")

st.sidebar.header("Workflow & Allowlist")
st.sidebar.write("Detect → Correlate → Triage → Report. Review allowlisted activity and triage incidents from the sample data set.")

if seeded_data:
    st.sidebar.caption("Demo mode enabled")

range_options = {
    "Last 14 days": 14,
    "Last 7 days": 7,
    "Last 24 hours": 1,
    "Last 1 hour": 1 / 24,
    "All time": None,
}
selected_window = st.sidebar.selectbox("Time range", list(range_options.keys()), index=0)
window_days = range_options[selected_window]
now = datetime.utcnow()
if window_days is None:
    start_ts = pd.Timestamp.min.tz_localize("UTC")
else:
    start_ts = pd.Timestamp(now - timedelta(days=window_days))

if not logs.empty:
    logs["ts"] = parse_timestamp_series(logs.get("timestamp", pd.Series(dtype="object")))
else:
    logs["ts"] = pd.Series(dtype="datetime64[ns, UTC]")
if not alerts.empty:
    alerts["ts"] = parse_timestamp_series(alerts.get("timestamp", pd.Series(dtype="object")))
else:
    alerts["ts"] = pd.Series(dtype="datetime64[ns, UTC]")

filtered_logs = logs if logs.empty or window_days is None else logs[logs["ts"] >= pd.Timestamp(start_ts, tz="UTC")]
filtered_alerts = alerts if alerts.empty or window_days is None else alerts[alerts["ts"] >= pd.Timestamp(start_ts, tz="UTC")]
filtered_incidents = incidents

if not filtered_logs.empty or not filtered_alerts.empty:
    if filtered_logs.empty and not filtered_alerts.empty:
        filtered_logs = pd.DataFrame(columns=logs.columns)
    if filtered_alerts.empty and not filtered_logs.empty:
        filtered_alerts = pd.DataFrame(columns=alerts.columns)

metric_cols = st.columns(4)
with metric_cols[0]:
    st.metric("Total logs", len(filtered_logs))
with metric_cols[1]:
    st.metric("Total alerts", len(filtered_alerts))
with metric_cols[2]:
    active_incidents = len([inc for inc in filtered_incidents if str(inc.get("disposition", "")).lower() in {"open", "investigating", "in_progress"}])
    st.metric("Active incidents", active_incidents)
with metric_cols[3]:
    highest_risk = int(filtered_alerts["risk_score"].max()) if not filtered_alerts.empty and "risk_score" in filtered_alerts.columns else 0
    st.metric("Peak risk", highest_risk)

if filtered_alerts.empty:
    render_empty_state("No alerts in the selected time range", "The current filters have no matching alert data. Expand the date range or seed the sample data.", "🚨")
    risk_col, chart_col = st.columns([1, 2])
    with risk_col:
        render_empty_state("Risk score unavailable", "No alert risk scores to summarize for this range.", "📊")
        st.progress(0.0)
        st.caption("0 / 100")
    with chart_col:
        render_empty_state("Trend chart is empty", "No time-series activity was detected for this filter window.", "📈")
else:
    risk_col, chart_col = st.columns([1, 2])
    with risk_col:
        risk_score = filtered_alerts["risk_score"].astype(float).max() if "risk_score" in filtered_alerts.columns else 0
        risk_percentage = min(max(risk_score / 100, 0), 1)
        st.markdown("### Risk score gauge")
        st.progress(risk_percentage)
        st.caption(f"Highest alert risk: {int(risk_score)}/100")
        risk_bucket = filtered_alerts["risk_level"].mode().iloc[0] if "risk_level" in filtered_alerts.columns and not filtered_alerts["risk_level"].empty else "unknown"
        st.write(f"Dominant risk level: {risk_bucket}")
    with chart_col:
        chart_df = filtered_alerts.copy()
        chart_df["ts"] = pd.to_datetime(chart_df["ts"], utc=True)
        hourly = chart_df.groupby(chart_df["ts"].dt.floor("H")).size().reset_index(name="count")
        hourly.columns = ["timestamp", "alerts"]
        fig = px.line(hourly, x="timestamp", y="alerts", title="Alert volume over time")
        st.plotly_chart(fig, use_container_width=True)

incident_table = pd.DataFrame(
    [
        {
            "incident_id": i.get("incident_id", "N/A"),
            "source_ip": i.get("source_ip", "N/A"),
            "severity": i.get("severity", "Unknown"),
            "status": i.get("status", i.get("disposition", "Open")),
            "kill_chain": i.get("kill_chain_stages", "") if isinstance(i.get("kill_chain_stages"), str) else " > ".join(i.get("kill_chain_stages", [])),
        }
        for i in incidents
    ]
)

if incident_table.empty:
    st.header("Incidents")
    render_empty_state("No incidents detected", "There are no correlated incidents in this window yet.", "🧭")
else:
    st.header("Incidents")
    st.dataframe(incident_table, use_container_width=True)

incident_options = [i.get("incident_id") for i in incidents if i.get("incident_id")]
if not incident_options:
    st.subheader("Incident details")
    render_empty_state("No incident selected", "Choose a seeded or generated incident to inspect its evidence and response notes.", "🧪")
else:
    selected_incident_id = st.selectbox("Select incident", options=incident_options)
    selected_incident = next((i for i in incidents if i.get("incident_id") == selected_incident_id), None)
    if selected_incident is None:
        render_empty_state("No incident details available", "The selected incident is not available in the current dataset.", "⚠️")
    else:
        st.subheader(f"Incident {selected_incident['incident_id']} details")
        st.write(f"Source IP: {selected_incident.get('source_ip', 'unknown')}")
        st.write(f"Severity: {selected_incident.get('severity', 'Unknown')}")
        st.write("Kill chain stages:", selected_incident.get("kill_chain_stages", []))
        st.write("Alerts:")
        alert_rows = selected_incident.get("alerts", []) if isinstance(selected_incident, dict) else []
        if not alert_rows:
            render_empty_state("This incident has no alert detail", "The currently selected incident is missing explicit alert evidence.", "🧾")
        else:
            for item in alert_rows:
                st.write(f"- {item.get('timestamp', 'unknown')} | {item.get('alert_type', 'unknown')} | {item.get('detail', '')}")

        if 'notes' not in st.session_state:
            st.session_state['notes'] = {}
        disposition_options = ['Open', 'Investigating', 'True Positive', 'False Positive', 'Benign', 'Resolved']
        current_disposition = selected_incident.get('disposition', 'Open')
        new_disp = st.selectbox('Disposition', options=disposition_options, index=disposition_options.index(current_disposition) if current_disposition in disposition_options else 0)
        note = st.text_area('Analyst notes', value=st.session_state['notes'].get(selected_incident['incident_id'], ''))
        if st.button('Save disposition'):
            selected_incident['disposition'] = new_disp
            st.session_state['notes'][selected_incident['incident_id']] = note
            st.success('Saved')

        if st.button('Generate Incident Report'):
            if len(selected_incident.get('kill_chain_stages', [])) >= 2:
                md = generate_markdown(selected_incident)
                st.markdown('---')
                st.markdown(md)
                st.download_button('Download report', data=md, file_name=f"incident_report_{selected_incident['incident_id']}.md")
            else:
                st.warning('Incident is single-stage; report generation reserved for multi-stage incidents')

        if alert_rows:
            df = pd.DataFrame(alert_rows)
            if not df.empty:
                df['ts'] = pd.to_datetime(df['timestamp'], errors='coerce')
                stage_map = {'port_scan': 'Recon', 'brute_force': 'Initial Access', 'privilege_escalation': 'Escalation', 'impossible_travel': 'Initial Access'}
                df['stage'] = df['alert_type'].map(stage_map)
                fig = px.scatter(df, x='ts', y=['source_ip'], color='stage', hover_data=['alert_type', 'detail'])
                st.plotly_chart(fig, use_container_width=True)

st.write('---')
if filtered_logs.empty:
    st.subheader('Logs preview')
    render_empty_state("No log entries in the selected range", "This workspace has no raw log data for the active filter window.", "🧾")
else:
    st.subheader('Logs preview')
    st.dataframe(filtered_logs.head(50), use_container_width=True)

if seeded_data:
    st.sidebar.success("Demo mode is on: seed data is being used for this walkthrough.")
else:
    st.sidebar.info("No seeded data detected yet. Run the seed command to populate sample SOC data.")

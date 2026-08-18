import streamlit as st
import pandas as pd
import json
from report_generator import generate_markdown
from datetime import datetime
import plotly.express as px

st.set_page_config(layout="wide")

st.title("SOC Analyst Workbench — Detect → Correlate → Triage → Report")

@st.cache_data
def load_logs():
    return pd.read_csv('logs.csv')

@st.cache_data
def load_alerts():
    return pd.read_csv('alerts.csv')

@st.cache_data
def load_incidents():
    with open('incidents.json') as f:
        return json.load(f)

logs = load_logs()
alerts = load_alerts()
incidents = load_incidents()

# Top metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total logs", len(logs))
col2.metric("Total alerts", len(alerts))
active_incidents = len([i for i in incidents if i.get('disposition') == 'Open'])
col3.metric("Active incidents", active_incidents)

# Simulated MTTD/MTTR
# MTTD: avg time between first malicious log event and alert timestamp

def compute_mttd(incidents):
    deltas = []
    for inc in incidents:
        if inc['alerts']:
            first_event = inc['start_time']
            # detection time is alert timestamp of first alert
            detected = inc['alerts'][0]['timestamp']
            t1 = datetime.strptime(first_event, '%Y-%m-%d %H:%M:%S')
            t2 = datetime.strptime(detected, '%Y-%m-%d %H:%M:%S')
            deltas.append((t2 - t1).total_seconds())
    if deltas:
        return sum(deltas)/len(deltas)
    return 0

mttd_seconds = compute_mttd(incidents)
mttr_seconds = 60 * 5  # mock 5 minutes
col4.metric("MTTD (s)", int(mttd_seconds), delta=None)

st.sidebar.header("Workflow & Allowlist")
st.sidebar.write("Detect → Correlate → Triage → Report. Allowlist entries are suppressed but visible for review.")

# Incidents table
st.header("Incidents")

inc_df = pd.DataFrame([{'incident_id': i['incident_id'], 'source_ip': i['source_ip'], 'severity': i['severity'], 'kill_chain': ' > '.join(i['kill_chain_stages']), 'disposition': i.get('disposition','Open')} for i in incidents])
st.dataframe(inc_df)

sel = st.selectbox('Select incident', options=[i['incident_id'] for i in incidents])
inc = next(i for i in incidents if i['incident_id'] == sel)

st.subheader(f"Incident {inc['incident_id']} details")
st.write(f"Source IP: {inc['source_ip']}")
st.write(f"Severity: {inc['severity']}")
st.write("Kill chain stages:", inc['kill_chain_stages'])

st.write("Alerts:")
for a in inc['alerts']:
    st.write(f"- {a['timestamp']} | {a['alert_type']} | {a.get('detail','')}")

# show suppressed alerts from alerts.csv for this IP
suppressed = alerts[(alerts.source_ip == inc['source_ip']) & (alerts.get('suppressed', False) == True)] if 'suppressed' in alerts.columns else pd.DataFrame()
if not suppressed.empty:
    st.write("Suppressed alerts (allowlist):")
    st.dataframe(suppressed)

# Disposition
if 'notes' not in st.session_state:
    st.session_state['notes'] = {}

new_disp = st.selectbox('Disposition', options=['Open','Investigating','True Positive','False Positive','Benign'], index=['Open','Investigating','True Positive','False Positive','Benign'].index(inc.get('disposition','Open')))
note = st.text_area('Analyst notes', value=st.session_state['notes'].get(inc['incident_id'], ''))
if st.button('Save disposition'):
    inc['disposition'] = new_disp
    st.session_state['notes'][inc['incident_id']] = note
    st.success('Saved')

# Generate report
if st.button('Generate Incident Report'):
    if len(inc.get('kill_chain_stages', [])) >= 2:
        md = generate_markdown(inc)
        st.markdown('---')
        st.markdown(md)
        st.download_button('Download report', data=md, file_name=f"incident_report_{inc['incident_id']}.md")
    else:
        st.warning('Incident is single-stage; report generation reserved for multi-stage incidents')

# timeline plot for incidents with >1 event
if len(inc['alerts']) >= 1:
    df = pd.DataFrame(inc['alerts'])
    df['ts'] = pd.to_datetime(df['timestamp'])
    df['stage'] = df['alert_type'].map({'port_scan':'Recon','brute_force':'Initial Access','privilege_escalation':'Escalation','impossible_travel':'Initial Access'})
    fig = px.scatter(df, x='ts', y=['source_ip'], color='stage', hover_data=['alert_type','detail'])
    st.plotly_chart(fig, use_container_width=True)

st.write('---')
st.write('Logs preview:')
st.dataframe(logs.head(50))

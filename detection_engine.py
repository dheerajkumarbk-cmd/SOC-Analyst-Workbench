import pandas as pd
from datetime import datetime, timedelta
import json

ALLOWLIST = ["198.51.100.42"]

# severity mapping
SEVERITY = {
    'brute_force': 'High',
    'port_scan': 'Medium',
    'impossible_travel': 'Medium',
    'privilege_escalation': 'Critical'
}

# map to MITRE
MITRE = {
    'brute_force': ('T1110', 'Brute Force / Credential Stuffing'),
    'port_scan': ('T1046', 'Port Scanning'),
    'impossible_travel': ('T1078', 'Valid Accounts / Impossible Travel'),
    'privilege_escalation': ('T1068', 'Exploitation for Privilege Escalation')
}

KILL_CHAIN = {
    'port_scan': 'Reconnaissance',
    'brute_force': 'Initial Access',
    'impossible_travel': 'Initial Access',
    'privilege_escalation': 'Privilege Escalation'
}


def parse_time(s):
    return datetime.strptime(s, '%Y-%m-%d %H:%M:%S')


def detect_alerts(df):
    alerts = []
    df['ts'] = df['timestamp'].apply(parse_time)

    # Port scan: >=6 distinct ports from same IP within 2 minutes
    grouped = df[df.event_type == 'port_scan'].groupby('source_ip')
    for ip, g in grouped:
        times_ports = g[['ts', 'destination_port']].sort_values('ts')
        for i in range(len(times_ports)):
            window_start = times_ports.ts.iloc[i]
            window_end = window_start + timedelta(minutes=2)
            slice_ = times_ports[(times_ports.ts >= window_start) & (times_ports.ts <= window_end)]
            if slice_.destination_port.nunique() >= 6:
                alerts.append({'timestamp': window_start.strftime('%Y-%m-%d %H:%M:%S'), 'source_ip': ip, 'alert_type': 'port_scan', 'detail': f"ports={sorted(slice_.destination_port.unique())}", 'mitre': MITRE['port_scan'][0], 'severity': SEVERITY['port_scan']})
                break

    # Brute force: >=5 failed logins same IP in 5 min
    failed = df[df.event_type == 'login_failed'].groupby('source_ip')
    for ip, g in failed:
        g = g.sort_values('ts')
        for i in range(len(g)):
            start = g.ts.iloc[i]
            end = start + timedelta(minutes=5)
            cnt = g[(g.ts >= start) & (g.ts <= end)].shape[0]
            if cnt >= 5:
                alerts.append({'timestamp': start.strftime('%Y-%m-%d %H:%M:%S'), 'source_ip': ip, 'alert_type': 'brute_force', 'detail': f'failed_count={cnt}', 'mitre': MITRE['brute_force'][0], 'severity': SEVERITY['brute_force']})
                break

    # Privilege escalation: event present within 10 min of a login_success for same IP
    success = df[df.event_type == 'login_success']
    priv = df[df.event_type == 'privilege_escalation']
    for idx, row in priv.iterrows():
        ip = row.source_ip
        t = row.ts
        # find login_success from same ip within 10 minutes before
        window = success[(success.source_ip == ip) & (success.ts <= t) & (success.ts >= t - timedelta(minutes=10))]
        if not window.empty:
            alerts.append({'timestamp': window.ts.min().strftime('%Y-%m-%d %H:%M:%S'), 'source_ip': ip, 'alert_type': 'privilege_escalation', 'detail': 'privilege escalation after login', 'mitre': MITRE['privilege_escalation'][0], 'severity': SEVERITY['privilege_escalation']})

    # Impossible travel: same username, two geo_locations within 30 minutes
    users = df.groupby('username')
    for user, g in users:
        g = g.sort_values('ts')
        for i in range(len(g)-1):
            t1 = g.ts.iloc[i]
            t2 = g.ts.iloc[i+1]
            if g.geo_location.iloc[i] != g.geo_location.iloc[i+1] and (t2 - t1) <= timedelta(minutes=30):
                alerts.append({'timestamp': t1.strftime('%Y-%m-%d %H:%M:%S'), 'source_ip': g.source_ip.iloc[i+1], 'alert_type': 'impossible_travel', 'detail': f'{user} from {g.geo_location.iloc[i]} to {g.geo_location.iloc[i+1]}', 'mitre': MITRE['impossible_travel'][0], 'severity': SEVERITY['impossible_travel']})
                break

    alerts_df = pd.DataFrame(alerts)
    if alerts_df.empty:
        alerts_df = pd.DataFrame(columns=['timestamp','source_ip','alert_type','detail','mitre','severity'])
    return alerts_df


def suppress_allowlist(alerts_df):
    if alerts_df.empty:
        return alerts_df
    alerts_df['suppressed'] = alerts_df['source_ip'].isin(ALLOWLIST)
    alerts_df['suppression_reason'] = alerts_df['suppressed'].apply(lambda x: 'suppressed: allowlisted admin IP' if x else '')
    return alerts_df


def correlate_incidents(alerts_df):
    incidents = []
    if alerts_df.empty:
        return incidents
    # only non-suppressed alerts
    active = alerts_df[alerts_df.suppressed == False].sort_values('timestamp')
    active['ts'] = active['timestamp'].apply(parse_time)

    # group by source_ip with a rolling 30-minute window
    grouped = active.groupby('source_ip')
    iid = 1
    for ip, g in grouped:
        g = g.sort_values('ts')
        if g.empty:
            continue
        current_incidents = []
        # simple approach: start a new incident with first alert, extend it while next alert within 30 mins
        st = g.ts.iloc[0]
        alerts_list = [g.iloc[0].to_dict()]
        for i in range(1, len(g)):
            if (g.ts.iloc[i] - g.ts.iloc[i-1]) <= timedelta(minutes=30):
                alerts_list.append(g.iloc[i].to_dict())
            else:
                # finalize incident
                stages = [KILL_CHAIN[a['alert_type']] for a in alerts_list]
                severity = max([a['severity'] for a in alerts_list], key=lambda s: ['Low','Medium','High','Critical'].index(s))
                incidents.append({'incident_id': f'I{iid:04d}', 'source_ip': ip, 'start_time': alerts_list[0]['timestamp'], 'alerts': alerts_list, 'severity': severity, 'kill_chain_stages': stages, 'disposition': 'Open'})
                iid += 1
                alerts_list = [g.iloc[i].to_dict()]
        if alerts_list:
            stages = [KILL_CHAIN[a['alert_type']] for a in alerts_list]
            severity = max([a['severity'] for a in alerts_list], key=lambda s: ['Low','Medium','High','Critical'].index(s))
            incidents.append({'incident_id': f'I{iid:04d}', 'source_ip': ip, 'start_time': alerts_list[0]['timestamp'], 'alerts': alerts_list, 'severity': severity, 'kill_chain_stages': stages, 'disposition': 'Open'})
            iid += 1

    return incidents


def main():
    df = pd.read_csv('logs.csv')
    alerts = detect_alerts(df)
    alerts = suppress_allowlist(alerts)
    alerts.to_csv('alerts.csv', index=False)
    incidents = correlate_incidents(alerts)
    with open('incidents.json', 'w') as f:
        json.dump(incidents, f, indent=2, default=str)
    print(f'Wrote {len(alerts)} alerts and {len(incidents)} incidents')


if __name__ == '__main__':
    main()

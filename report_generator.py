import json
from datetime import datetime

MITRE_NAMES = {
    'T1110': 'Brute Force',
    'T1046': 'Port Scanning',
    'T1078': 'Valid Accounts',
    'T1068': 'Privilege Escalation'
}

REMEDIATIONS = {
    'brute_force': ["Enforce account lockout", "Enable MFA", "Monitor for credential stuffing"],
    'port_scan': ["Block offending IP", "Rate-limit connections", "Network-level IDS/IPS"],
    'privilege_escalation': ["Rotate impacted credentials", "Review recent changes", "Harden privilege assignments"],
    'impossible_travel': ["Verify user activity", "Consider MFA or password reset"]
}

SEVERITY_TEXT = {
    'Low': 'Limited impact expected.',
    'Medium': 'Moderate impact; investigate promptly.',
    'High': 'High impact; immediate investigation recommended.',
    'Critical': 'Severe impact; urgent response required.'
}


def generate_markdown(incident):
    iid = incident['incident_id']
    title = f"Incident {iid} - {incident['source_ip']}"
    severity = incident['severity']
    summary = f"Detected incident {iid} involving {incident['source_ip']} with severity {severity}. Kill chain: {', '.join(incident['kill_chain_stages'])}."

    md = [f"# {title}", "", f"**Summary:** {summary}", "", "## Timeline", "", "| Timestamp | Event | Detail |", "|---|---|---|"]
    for a in incident['alerts']:
        ts = a.get('timestamp')
        ev = a.get('alert_type')
        detail = a.get('detail', '')
        md.append(f"| {ts} | {ev} | {detail} |")

    md.append("")
    md.append("## Indicators of Compromise")
    iocs = [f"- Source IP: {incident['source_ip']}", f"- Severity: {severity}"]
    users = set([a.get('detail','') for a in incident['alerts'] if 'username' in a.get('detail','')])
    md.extend(iocs)
    md.append("")
    md.append("## MITRE Techniques")
    for a in incident['alerts']:
        mitre = a.get('mitre')
        if mitre:
            md.append(f"- {mitre}: {MITRE_NAMES.get(mitre, '')}")

    md.append("")
    md.append("## Impact Assessment")
    md.append(SEVERITY_TEXT.get(severity, 'Investigate impact.'))
    md.append("")
    md.append("## Recommended Remediation")
    rems = set()
    for a in incident['alerts']:
        t = a.get('alert_type')
        for r in REMEDIATIONS.get(t, []):
            rems.add(r)
    for r in rems:
        md.append(f"- {r}")

    return '\n'.join(md)


def main():
    with open('incidents.json') as f:
        incidents = json.load(f)
    for inc in incidents:
        # only generate for multi-stage incidents
        if len(inc.get('kill_chain_stages', [])) >= 2:
            md = generate_markdown(inc)
            fn = f"incident_report_{inc['incident_id']}.md"
            with open(fn, 'w') as out:
                out.write(md)
            print('Wrote', fn)


if __name__ == '__main__':
    main()

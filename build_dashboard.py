import json
import pandas as pd
from pathlib import Path

INC_FILE = Path('incidents.json')
ALERTS_FILE = Path('alerts.csv')
LOGS_FILE = Path('logs.csv')
OUT = Path('dashboard.html')


def load_data():
    incidents = json.loads(INC_FILE.read_text()) if INC_FILE.exists() else []
    alerts = pd.read_csv(ALERTS_FILE) if ALERTS_FILE.exists() else pd.DataFrame()
    logs = pd.read_csv(LOGS_FILE) if LOGS_FILE.exists() else pd.DataFrame()
    return incidents, alerts, logs


def make_incident_row_html(inc):
    stages = ' → '.join(inc.get('kill_chain_stages', []))
    return f"<tr data-iid=\"{inc['incident_id']}\"><td>{inc['incident_id']}</td><td>{inc['source_ip']}</td><td>{inc['severity']}</td><td>{stages}</td><td>{inc.get('disposition','Open')}</td></tr>"


def incident_alerts_div(inc):
    rows = []
    for a in inc['alerts']:
        rows.append(f"<tr><td>{a.get('timestamp')}</td><td>{a.get('alert_type')}</td><td>{a.get('detail','')}</td></tr>")
    table = '<table class="inner"><thead><tr><th>Timestamp</th><th>Event</th><th>Detail</th></tr></thead><tbody>' + '\n'.join(rows) + '</tbody></table>'
    return f"<div class=\"incident-details\" id=\"details-{inc['incident_id']}\">{table}<p><a href=\"incident_report_{inc['incident_id']}.md\">Download report</a></p></div>"


def build():
    incidents, alerts, logs = load_data()
    incidents_html = '\n'.join([make_incident_row_html(i) for i in incidents])
    details_html = '\n'.join([incident_alerts_div(i) for i in incidents])

    template = """
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>SOC Analyst Workbench — Dashboard</title>
      <style>
        body { font-family: Arial, sans-serif; margin:20px }
        table { border-collapse: collapse; width: 100%; margin-bottom: 1rem }
        table, th, td { border: 1px solid #ddd }
        th, td { padding: 8px }
        tr:hover { background:#f6f6f6; cursor:pointer }
        .incident-details { display:none; margin: 10px 0 20px 0 }
        .inner { width: 100% }
      </style>
    </head>
    <body>
      <h1>SOC Analyst Workbench — Dashboard (Static)</h1>
      <p>Click an incident row to reveal details and download the generated report.</p>
      <h2>Incidents</h2>
      <table id="incidents">
        <thead><tr><th>ID</th><th>Source IP</th><th>Severity</th><th>Kill Chain</th><th>Disposition</th></tr></thead>
        <tbody>
        __INCIDENTS__
        </tbody>
      </table>

      <div id="details">
        __DETAILS__
      </div>

      <script>
        const rows = document.querySelectorAll('#incidents tbody tr');
        rows.forEach(r => {
          r.addEventListener('click', function() {
            const iid = this.getAttribute('data-iid');
            // hide all
            document.querySelectorAll('.incident-details').forEach(function(d){ d.style.display='none' });
            const det = document.getElementById('details-' + iid);
            if (det) det.style.display = 'block';
            if (det) det.scrollIntoView({behavior:'smooth'});
          });
        });
      </script>
    </body>
    </html>
    """

    html = template.replace('__INCIDENTS__', incidents_html).replace('__DETAILS__', details_html)

    OUT.write_text(html)
    print('Wrote', OUT.resolve())


if __name__ == '__main__':
  build()

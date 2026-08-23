import argparse
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "backend" / "data" / "soc_workbench.db"


def to_sqlite_ts(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def seed_logs() -> List[Dict[str, object]]:
    now = datetime.utcnow().replace(microsecond=0)
    base_time = now - timedelta(days=14)
    samples = [
        {"timestamp": base_time + timedelta(hours=2, minutes=10), "source_ip": "203.0.113.12", "event_type": "auth_failure", "username": "jdoe", "destination_port": 22, "geo_location": "US", "details": "Repeated MFA challenge failures"},
        {"timestamp": base_time + timedelta(hours=3, minutes=18), "source_ip": "198.51.100.77", "event_type": "auth_failure", "username": "mgarcia", "destination_port": 3389, "geo_location": "US", "details": "Remote desktop authentication fail"},
        {"timestamp": base_time + timedelta(hours=6, minutes=42), "source_ip": "203.0.113.19", "event_type": "port_scan", "username": "svc-ops", "destination_port": 443, "geo_location": "DE", "details": "Scanning for exposed services"},
        {"timestamp": base_time + timedelta(days=1, hours=1, minutes=47), "source_ip": "192.0.2.101", "event_type": "malware", "username": "alice", "destination_port": 443, "geo_location": "US", "details": "Outbound HTTP beacon to suspicious domain"},
        {"timestamp": base_time + timedelta(days=1, hours=3, minutes=14), "source_ip": "203.0.113.55", "event_type": "auth_failure", "username": "nina", "destination_port": 22, "geo_location": "RU", "details": "Credential stuffing burst"},
        {"timestamp": base_time + timedelta(days=1, hours=4, minutes=8), "source_ip": "198.51.100.15", "event_type": "dns_anomaly", "username": "analyst", "destination_port": 53, "geo_location": "US", "details": "High entropy DNS query to rare domain"},
        {"timestamp": base_time + timedelta(days=1, hours=6, minutes=5), "source_ip": "198.51.100.40", "event_type": "outbound_traffic", "username": "svc-backup", "destination_port": 443, "geo_location": "US", "details": "Large upload to unknown host"},
        {"timestamp": base_time + timedelta(days=2, hours=2, minutes=44), "source_ip": "203.0.113.86", "event_type": "port_scan", "username": "svc-scan", "destination_port": 8443, "geo_location": "CN", "details": "Targeted port sweep across multiple hosts"},
        {"timestamp": base_time + timedelta(days=2, hours=5, minutes=27), "source_ip": "203.0.113.70", "event_type": "malware", "username": "bob", "destination_port": 4444, "geo_location": "JP", "details": "PowerShell encoded payload execution"},
        {"timestamp": base_time + timedelta(days=2, hours=7, minutes=2), "source_ip": "198.51.100.32", "event_type": "dns_anomaly", "username": "kevin", "destination_port": 53, "geo_location": "BR", "details": "Fast-flux style lookups"},
        {"timestamp": base_time + timedelta(days=3, hours=1, minutes=12), "source_ip": "203.0.113.41", "event_type": "auth_failure", "username": "csmith", "destination_port": 22, "geo_location": "US", "details": "Repeated LDAP login failures"},
        {"timestamp": base_time + timedelta(days=3, hours=3, minutes=39), "source_ip": "203.0.113.99", "event_type": "outbound_traffic", "username": "ops-user", "destination_port": 80, "geo_location": "US", "details": "Unusual outbound transfer to external IP"},
        {"timestamp": base_time + timedelta(days=3, hours=8, minutes=50), "source_ip": "203.0.113.55", "event_type": "port_scan", "username": "root", "destination_port": 8080, "geo_location": "RU", "details": "Web service enumeration"},
        {"timestamp": base_time + timedelta(days=4, hours=12, minutes=50), "source_ip": "198.51.100.82", "event_type": "auth_failure", "username": "jones", "destination_port": 443, "geo_location": "DE", "details": "VPN challenge retries"},
        {"timestamp": base_time + timedelta(days=4, hours=14, minutes=4), "source_ip": "192.0.2.44", "event_type": "dns_anomaly", "username": "dora", "destination_port": 53, "geo_location": "US", "details": "Long subdomain sequence"},
        {"timestamp": base_time + timedelta(days=5, hours=2, minutes=22), "source_ip": "203.0.113.132", "event_type": "malware", "username": "svc-win", "destination_port": 445, "geo_location": "US", "details": "Suspicious DLL loading"},
        {"timestamp": base_time + timedelta(days=5, hours=6, minutes=16), "source_ip": "198.51.100.18", "event_type": "outbound_traffic", "username": "noreply", "destination_port": 443, "geo_location": "US", "details": "Rare data exfil via HTTPS"},
        {"timestamp": base_time + timedelta(days=6, hours=4, minutes=19), "source_ip": "203.0.113.77", "event_type": "auth_failure", "username": "slee", "destination_port": 22, "geo_location": "IN", "details": "SSH brute force attempts"},
        {"timestamp": base_time + timedelta(days=6, hours=8, minutes=48), "source_ip": "203.0.113.91", "event_type": "malware", "username": "finance", "destination_port": 443, "geo_location": "US", "details": "Beaconing to malware C2"},
        {"timestamp": base_time + timedelta(days=7, hours=2, minutes=30), "source_ip": "198.51.100.91", "event_type": "port_scan", "username": "ops", "destination_port": 8443, "geo_location": "US", "details": "Sequential scan over internal range"},
        {"timestamp": base_time + timedelta(days=7, hours=5, minutes=41), "source_ip": "198.51.100.15", "event_type": "outbound_traffic", "username": "admin", "destination_port": 443, "geo_location": "US", "details": "Unexpected large outbound transfer"},
        {"timestamp": base_time + timedelta(days=8, hours=1, minutes=38), "source_ip": "203.0.113.50", "event_type": "dns_anomaly", "username": "kwong", "destination_port": 53, "geo_location": "CN", "details": "High-frequency DNS tunneling"},
        {"timestamp": base_time + timedelta(days=8, hours=7, minutes=51), "source_ip": "198.51.100.14", "event_type": "auth_failure", "username": "guest", "destination_port": 22, "geo_location": "CA", "details": "Automated login attempts"},
        {"timestamp": base_time + timedelta(days=9, hours=10, minutes=11), "source_ip": "203.0.113.21", "event_type": "outbound_traffic", "username": "courier", "destination_port": 443, "geo_location": "US", "details": "Data transfer over suspicious several GB"},
        {"timestamp": base_time + timedelta(days=9, hours=15, minutes=13), "source_ip": "203.0.113.72", "event_type": "malware", "username": "sleeper", "destination_port": 445, "geo_location": "US", "details": "Process hollowing indicators"},
        {"timestamp": base_time + timedelta(days=10, hours=2, minutes=41), "source_ip": "203.0.113.55", "event_type": "outbound_traffic", "username": "alice", "destination_port": 443, "geo_location": "RU", "details": "Unexpected outbound transfer to egress host"},
        {"timestamp": base_time + timedelta(days=10, hours=4, minutes=38), "source_ip": "203.0.113.119", "event_type": "auth_failure", "username": "mendes", "destination_port": 3389, "geo_location": "US", "details": "Failed VPN sign-ins"},
        {"timestamp": base_time + timedelta(days=10, hours=6, minutes=58), "source_ip": "198.51.100.6", "event_type": "port_scan", "username": "db-user", "destination_port": 21, "geo_location": "DE", "details": "Recon attempt against services"},
        {"timestamp": base_time + timedelta(days=11, hours=1, minutes=2), "source_ip": "198.51.100.3", "event_type": "dns_anomaly", "username": "ops", "destination_port": 53, "geo_location": "US", "details": "Rare TXT record lookups"},
        {"timestamp": base_time + timedelta(days=11, hours=5, minutes=34), "source_ip": "203.0.113.88", "event_type": "malware", "username": "svc-rdp", "destination_port": 4444, "geo_location": "JP", "details": "Downloader staged from suspicious host"},
        {"timestamp": base_time + timedelta(days=12, hours=1, minutes=7), "source_ip": "203.0.113.44", "event_type": "dns_anomaly", "username": "admin", "destination_port": 53, "geo_location": "US", "details": "Domain generation algorithm query"},
        {"timestamp": base_time + timedelta(days=12, hours=9, minutes=22), "source_ip": "203.0.113.57", "event_type": "auth_failure", "username": "rob", "destination_port": 22, "geo_location": "IN", "details": "Brute force on bastion host"},
        {"timestamp": base_time + timedelta(days=12, hours=12, minutes=37), "source_ip": "198.51.100.25", "event_type": "outbound_traffic", "username": "analyst", "destination_port": 443, "geo_location": "US", "details": "Unusual uploads to DLP bypass path"},
        {"timestamp": base_time + timedelta(days=13, hours=3, minutes=8), "source_ip": "203.0.113.70", "event_type": "dns_anomaly", "username": "bob", "destination_port": 53, "geo_location": "JP", "details": "Persistent DNS tunnel to suspicious domain"},
        {"timestamp": base_time + timedelta(days=13, hours=6, minutes=43), "source_ip": "203.0.113.70", "event_type": "outbound_traffic", "username": "bob", "destination_port": 443, "geo_location": "JP", "details": "Exfiltration burst to remote server"},
        {"timestamp": base_time + timedelta(days=13, hours=9, minutes=28), "source_ip": "203.0.113.108", "event_type": "port_scan", "username": "svc-solaris", "destination_port": 80, "geo_location": "US", "details": "Network reconnaissance against web footprint"},
        {"timestamp": base_time + timedelta(days=13, hours=16, minutes=50), "source_ip": "198.51.100.11", "event_type": "malware", "username": "helpdesk", "destination_port": 8080, "geo_location": "US", "details": "Malicious macro download"},
        {"timestamp": now - timedelta(days=1, hours=2), "source_ip": "203.0.113.91", "event_type": "malware", "username": "finance", "destination_port": 80, "geo_location": "US", "details": "Credential theft payload beacon"},
        {"timestamp": now - timedelta(days=1, hours=1), "source_ip": "198.51.100.92", "event_type": "auth_failure", "username": "ops", "destination_port": 22, "geo_location": "US", "details": "Password spray against admin accounts"},
        {"timestamp": now - timedelta(hours=6), "source_ip": "203.0.113.61", "event_type": "outbound_traffic", "username": "db", "destination_port": 443, "geo_location": "FR", "details": "Suspicious encrypted transfer pattern"},
        {"timestamp": now - timedelta(hours=3), "source_ip": "203.0.113.70", "event_type": "auth_failure", "username": "bob", "destination_port": 22, "geo_location": "JP", "details": "Credential stuffing from region mismatch"},
        {"timestamp": now - timedelta(hours=2), "source_ip": "198.51.100.8", "event_type": "malware", "username": "temp-user", "destination_port": 443, "geo_location": "US", "details": "Ransomware loader calling C2"},
    ]
    return [{**row, "timestamp": to_sqlite_ts(row["timestamp"])} for row in samples]


def seed_alerts(logs: List[Dict[str, object]]) -> List[Dict[str, object]]:
    incident_lookup = {
        "203.0.113.70": "INC-1001",
        "203.0.113.55": "INC-1002",
        "198.51.100.15": "INC-1003",
        "203.0.113.91": "INC-1004",
        "203.0.113.61": "INC-1005",
    }

    picked = [
        next(row for row in logs if row["source_ip"] == "203.0.113.55" and row["event_type"] == "auth_failure"),
        next(row for row in logs if row["source_ip"] == "203.0.113.55" and row["event_type"] == "port_scan"),
        next(row for row in logs if row["source_ip"] == "203.0.113.70" and row["event_type"] == "malware"),
        next(row for row in logs if row["source_ip"] == "203.0.113.70" and row["event_type"] == "dns_anomaly"),
        next(row for row in logs if row["source_ip"] == "203.0.113.70" and row["event_type"] == "outbound_traffic"),
        next(row for row in logs if row["source_ip"] == "198.51.100.15" and row["event_type"] == "outbound_traffic"),
        next(row for row in logs if row["source_ip"] == "198.51.100.15" and row["event_type"] == "dns_anomaly"),
        next(row for row in logs if row["source_ip"] == "203.0.113.91" and row["event_type"] == "malware"),
        next(row for row in logs if row["source_ip"] == "203.0.113.61" and row["event_type"] == "outbound_traffic"),
        next(row for row in logs if row["source_ip"] == "198.51.100.92" and row["event_type"] == "auth_failure"),
        next(row for row in logs if row["source_ip"] == "203.0.113.12" and row["event_type"] == "auth_failure"),
        next(row for row in logs if row["source_ip"] == "203.0.113.86" and row["event_type"] == "port_scan"),
        next(row for row in logs if row["source_ip"] == "198.51.100.82" and row["event_type"] == "auth_failure"),
        next(row for row in logs if row["source_ip"] == "203.0.113.132" and row["event_type"] == "malware"),
        next(row for row in logs if row["source_ip"] == "198.51.100.32" and row["event_type"] == "dns_anomaly"),
        next(row for row in logs if row["source_ip"] == "203.0.113.50" and row["event_type"] == "dns_anomaly"),
        next(row for row in logs if row["source_ip"] == "198.51.100.8" and row["event_type"] == "malware"),
        next(row for row in logs if row["source_ip"] == "203.0.113.44" and row["event_type"] == "dns_anomaly"),
    ]

    risk_profile = {
        "auth_failure": ("medium", 55, "Investigate", "investigate", "authentication_anomaly"),
        "port_scan": ("high", 78, "Investigate", "investigate", "port_scan"),
        "malware": ("critical", 93, "Block", "block", "malware_detection"),
        "dns_anomaly": ("low", 32, "Monitor", "monitor", "dns_anomaly"),
        "outbound_traffic": ("medium", 62, "Investigate", "investigate", "unusual_outbound_traffic"),
    }

    alerts = []
    for row in picked:
        risk_level, risk_score, suggested_response, response_action, alert_type = risk_profile[row["event_type"]]
        incident_id = incident_lookup.get(row["source_ip"])
        alerts.append({
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "alert_type": alert_type,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "suggested_response": suggested_response,
            "response_action": response_action,
            "detail": row["details"],
            "incident_id": incident_id,
        })

    alerts.append({
        "timestamp": logs[-1]["timestamp"],
        "source_ip": "203.0.113.70",
        "alert_type": "malware_detection",
        "risk_level": "critical",
        "risk_score": 97,
        "suggested_response": "Block",
        "response_action": "block",
        "detail": "Credential theft payload beacon",
        "incident_id": "INC-1001",
    })
    alerts.append({
        "timestamp": logs[-2]["timestamp"],
        "source_ip": "198.51.100.15",
        "alert_type": "unusual_outbound_traffic",
        "risk_level": "high",
        "risk_score": 81,
        "suggested_response": "Investigate",
        "response_action": "investigate",
        "detail": "Unexpected large outbound transfer",
        "incident_id": "INC-1003",
    })
    return sorted(alerts, key=lambda entry: entry["timestamp"])


def seed_incidents(alerts: List[Dict[str, object]]) -> List[Dict[str, object]]:
    grouped = {}
    for alert in alerts:
        incident_id = alert["incident_id"]
        if incident_id:
            grouped.setdefault(incident_id, []).append(alert)

    incident_rows = [
        {
            "incident_id": "INC-1001",
            "source_ip": "203.0.113.70",
            "start_time": "2026-08-11 07:00:00",
            "severity": "Critical",
            "status": "in_progress",
            "disposition": "Investigating",
            "kill_chain_stages": "Reconnaissance > Credential Access > Exfiltration",
            "alert_count": 5,
            "last_updated": "2026-08-24 08:30:00",
        },
        {
            "incident_id": "INC-1002",
            "source_ip": "203.0.113.55",
            "start_time": "2026-08-16 04:10:00",
            "severity": "High",
            "status": "in_progress",
            "disposition": "Investigating",
            "kill_chain_stages": "Authentication Abuse > Port Scan > Lateral Movement",
            "alert_count": 4,
            "last_updated": "2026-08-24 09:15:00",
        },
        {
            "incident_id": "INC-1003",
            "source_ip": "198.51.100.15",
            "start_time": "2026-08-19 14:42:00",
            "severity": "Medium",
            "status": "resolved",
            "disposition": "Contained",
            "kill_chain_stages": "DNS Anomaly > Exfiltration",
            "alert_count": 2,
            "last_updated": "2026-08-22 15:00:00",
        },
        {
            "incident_id": "INC-1004",
            "source_ip": "203.0.113.91",
            "start_time": "2026-08-23 11:30:00",
            "severity": "Critical",
            "status": "in_progress",
            "disposition": "Blocked",
            "kill_chain_stages": "Malware Beaconing > Credential Theft",
            "alert_count": 2,
            "last_updated": "2026-08-24 07:40:00",
        },
        {
            "incident_id": "INC-1005",
            "source_ip": "203.0.113.61",
            "start_time": "2026-08-24 10:05:00",
            "severity": "Low",
            "status": "resolved",
            "disposition": "Closed",
            "kill_chain_stages": "Outbound Data Transfer",
            "alert_count": 1,
            "last_updated": "2026-08-24 10:55:00",
        },
    ]
    return incident_rows


def create_schema(conn: sqlite3.Connection):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            event_type TEXT,
            username TEXT,
            destination_port INTEGER,
            geo_location TEXT,
            details TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            alert_type TEXT,
            risk_level TEXT,
            risk_score INTEGER,
            suggested_response TEXT,
            response_action TEXT,
            detail TEXT,
            incident_id TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            source_ip TEXT,
            start_time TEXT,
            severity TEXT,
            status TEXT,
            disposition TEXT,
            kill_chain_stages TEXT,
            alert_count INTEGER,
            last_updated TEXT
        )
        """
    )
    conn.execute("DELETE FROM logs")
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM incidents")
    conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Seed the SOC Workbench SQLite database with sample security data.")
    parser.add_argument("--db-path", type=str, default=str(DB_PATH), help="Path to the SQLite database file.")
    args = parser.parse_args()

    db_path = Path(args.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    try:
        create_schema(conn)
        logs = seed_logs()
        alerts = seed_alerts(logs)
        incidents = seed_incidents(alerts)

        conn.executemany(
            "INSERT INTO logs (timestamp, source_ip, event_type, username, destination_port, geo_location, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (row["timestamp"], row["source_ip"], row["event_type"], row["username"], row["destination_port"], row["geo_location"], row["details"])
                for row in logs
            ],
        )
        conn.executemany(
            "INSERT INTO alerts (timestamp, source_ip, alert_type, risk_level, risk_score, suggested_response, response_action, detail, incident_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    row["timestamp"],
                    row["source_ip"],
                    row["alert_type"],
                    row["risk_level"],
                    row["risk_score"],
                    row["suggested_response"],
                    row["response_action"],
                    row["detail"],
                    row["incident_id"],
                )
                for row in alerts
            ],
        )
        conn.executemany(
            "INSERT INTO incidents (incident_id, source_ip, start_time, severity, status, disposition, kill_chain_stages, alert_count, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    row["incident_id"],
                    row["source_ip"],
                    row["start_time"],
                    row["severity"],
                    row["status"],
                    row["disposition"],
                    row["kill_chain_stages"],
                    row["alert_count"],
                    row["last_updated"],
                )
                for row in incidents
            ],
        )
        conn.commit()
        print(f"Seeded {len(logs)} logs, {len(alerts)} alerts, and {len(incidents)} incidents into {db_path}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()

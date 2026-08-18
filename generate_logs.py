import csv
import random
from datetime import datetime, timedelta
import pandas as pd

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

NUM_LOGS = 2000
START = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=6)

ATTACKER_IP = "203.0.113.55"
ALLOWLIST_ADMIN_IP = "198.51.100.42"

USERNAMES = ["alice", "bob", "carol", "dave", "eve", "frank", "mallory"]
GEO = ["US", "DE", "IN", "JP", "BR", "CN"]
EVENT_TYPES = ["login_success", "login_failed", "port_scan", "privilege_escalation"]


def make_normal_noise(start_ts, n):
    rows = []
    for _ in range(n):
        ts = start_ts + timedelta(seconds=random.randint(0, 6 * 3600))
        src_ip = f"192.0.2.{random.randint(1,250)}"
        username = random.choice(USERNAMES)
        event = random.choices(["login_success", "login_failed"], weights=[0.7, 0.3])[0]
        dst_port = random.choice([22, 80, 443, 3389, 8080, random.randint(1024, 65535)])
        geo = random.choice(GEO)
        rows.append({"timestamp": ts, "source_ip": src_ip, "username": username, "event_type": event, "destination_port": dst_port, "geo_location": geo})
    return rows


def inject_attack_chain(start_ts):
    # Create a 20-minute window attack chain from ATTACKER_IP
    rows = []
    base = start_ts + timedelta(seconds=random.randint(0, 3600))

    # port scan: 8 distinct ports within 2 minutes
    scan_time = base
    ports = random.sample(range(1000, 1100), 8)
    for p in ports:
        rows.append({"timestamp": scan_time + timedelta(seconds=random.randint(0, 90)), "source_ip": ATTACKER_IP, "username": random.choice(USERNAMES), "event_type": "port_scan", "destination_port": p, "geo_location": "RU"})

    # burst of failed logins (brute force)
    bf_start = base + timedelta(minutes=5)
    for i in range(12):
        rows.append({"timestamp": bf_start + timedelta(seconds=i * 30), "source_ip": ATTACKER_IP, "username": random.choice(USERNAMES), "event_type": "login_failed", "destination_port": random.choice([22, 3389, 80]), "geo_location": "RU"})

    # one successful login
    success_time = bf_start + timedelta(minutes=6)
    rows.append({"timestamp": success_time, "source_ip": ATTACKER_IP, "username": "alice", "event_type": "login_success", "destination_port": 22, "geo_location": "RU"})

    # privilege escalation within 10 minutes
    rows.append({"timestamp": success_time + timedelta(minutes=3), "source_ip": ATTACKER_IP, "username": "alice", "event_type": "privilege_escalation", "destination_port": 22, "geo_location": "RU"})

    return rows


def inject_admin_activity(start_ts):
    rows = []
    # 2-3 logins from allowlist admin IP
    for i in range(3):
        ts = start_ts + timedelta(seconds=random.randint(0, 6 * 3600))
        rows.append({"timestamp": ts, "source_ip": ALLOWLIST_ADMIN_IP, "username": "admin", "event_type": random.choice(["login_failed", "login_success"]), "destination_port": 22, "geo_location": "US"})
    return rows


def main():
    rows = []
    rows.extend(make_normal_noise(START, NUM_LOGS - 20))
    rows.extend(inject_attack_chain(START))
    rows.extend(inject_admin_activity(START))

    # shuffle and save
    random.shuffle(rows)
    df = pd.DataFrame(rows)
    df.sort_values("timestamp", inplace=True)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    df.to_csv("logs.csv", index=False)
    print("Wrote logs.csv with", len(df), "rows")


if __name__ == "__main__":
    main()

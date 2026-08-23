import sqlite3
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "backend" / "data" / "soc_workbench.db"


def test_seed_database_has_realistic_sample_data():
    assert DB_PATH.exists(), "seed database should exist after running the seed script"

    conn = sqlite3.connect(DB_PATH)
    try:
        logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        risk_levels = conn.execute(
            "SELECT risk_level, COUNT(*) FROM alerts GROUP BY risk_level"
        ).fetchall()
        statuses = conn.execute(
            "SELECT status, COUNT(*) FROM incidents GROUP BY status"
        ).fetchall()
    finally:
        conn.close()

    assert 30 <= logs <= 50, "logs should be seeded within the requested range"
    assert 12 <= alerts <= 24, "alerts should be seeded within the requested range"
    assert incidents >= 4, "at least a few incidents should exist"
    assert {level for level, _ in risk_levels} >= {"low", "medium", "high", "critical"}, "risk spread should include all major levels"
    assert {status for status, _ in statuses} >= {"in_progress", "resolved"}, "workflow should include active and resolved state examples"

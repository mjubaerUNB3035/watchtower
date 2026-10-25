# WatchTower detection service: database access for the alerts table.
#
# This file is the only place in the detection service that talks SQL.
# It mirrors services/ingest/database.py: that one owns the events table,
# this one owns the alerts table.

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

# Load the project .env file (two folders up from this file).
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

DATABASE_URL = (
    f"postgresql+psycopg://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}"
    f"@localhost:5433/{os.getenv('POSTGRES_DB')}"
)

engine = create_engine(DATABASE_URL)


def save_alert(alert: dict) -> int:
    """Insert one alert row and return the new alert id."""
    sql = text(
        """
        INSERT INTO alerts (rule_name, severity, mitre_technique, host, source_ip,
                            username, event_count, window_start, window_end, event_ids)
        VALUES (:rule_name, :severity, :mitre_technique, :host, :source_ip,
                :username, :event_count, :window_start, :window_end, :event_ids)
        RETURNING id
        """
    )
    with engine.begin() as connection:
        new_id = connection.execute(sql, alert).scalar_one()
    return new_id

# Restrict Duplicate Alerts
def alert_exists(rule_name: str, event_ids: list[int]) -> bool:
    """True when an alert with this rule and these exact event ids exists."""
    sql = text(
        "SELECT COUNT(*) FROM alerts "
        "WHERE rule_name = :rule_name AND event_ids = CAST(:event_ids AS BIGINT[])"
    )
    with engine.connect() as connection:
        count = connection.execute(
            sql, {"rule_name": rule_name, "event_ids": event_ids}
        ).scalar_one()
    return count > 0

# services/detection/database.py
# detection database access, alerts table only

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

# load .env from project root
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

DATABASE_URL = (
    f"postgresql+psycopg://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}"
    f"@localhost:5433/{os.getenv('POSTGRES_DB')}"
)

engine = create_engine(DATABASE_URL)


def save_alert(alert: dict) -> int:
    # insert one alert into alerts, return new id
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


def alert_exists(rule_name: str, event_ids: list[int]) -> bool:
    # true if this rule and event ids already exist in alerts
    sql = text(
        "SELECT COUNT(*) FROM alerts "
        "WHERE rule_name = :rule_name AND event_ids = CAST(:event_ids AS BIGINT[])"
    )
    with engine.connect() as connection:
        count = connection.execute(
            sql, {"rule_name": rule_name, "event_ids": event_ids}
        ).scalar_one()
    return count > 0

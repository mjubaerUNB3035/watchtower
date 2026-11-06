# services/ingest/database.py
# ingest database access, events table only

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

from services.ingest.schema import SchemaEventIn

# load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

# database url from .env values
DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_NAME = os.getenv("POSTGRES_DB")
DATABASE_URL = (
    f"postgresql+psycopg://{DB_USER}:{DB_PASSWORD}"
    f"@localhost:5433/{DB_NAME}"
)

engine = create_engine(DATABASE_URL)


def save_event(event: SchemaEventIn) -> int:
    # insert one event into events, return new id
    sql = text(
        """
        INSERT INTO events
            (event_time, host, source, event_type,
             username, source_ip, outcome, raw)
        VALUES
            (:event_time, :host, :source, :event_type,
             :username, :source_ip, :outcome, :raw)
        RETURNING id
        """
    )
    values = {
        "event_time": event.event_time,
        "host": event.host,
        "source": event.source,
        "event_type": event.event_type,
        "username": event.username,
        "source_ip": event.source_ip,
        "outcome": event.outcome,
        "raw": event.raw,
    }
    with engine.begin() as connection:
        new_id = connection.execute(sql, values).scalar_one()
    return new_id


def search_events(source=None, event_type=None, username=None,
                  source_ip=None, limit=100):
    # search events by optional filters, return rows as dicts
    sql = ("SELECT id, event_time, host, source, event_type, username, "
           "source_ip, outcome, raw, received_at FROM events")
    conditions = []
    values = {}

    # only the filters the caller passed
    if source is not None:
        conditions.append("source = :source")
        values["source"] = source
    if event_type is not None:
        conditions.append("event_type = :event_type")
        values["event_type"] = event_type
    if username is not None:
        conditions.append("username = :username")
        values["username"] = username
    if source_ip is not None:
        conditions.append("source_ip = :source_ip")
        values["source_ip"] = source_ip

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    sql += " ORDER BY id LIMIT :limit"
    values["limit"] = limit

    with engine.connect() as connection:
        rows = connection.execute(text(sql), values).mappings().all()

    return [dict(row) for row in rows]

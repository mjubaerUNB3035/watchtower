# WatchTower ingest database helper
# This file is the only place in the ingest service that
# talks to PostgreSQL. main.py calls save_event() and does
# not need to know SQL or the database login.
# The login comes from the project .env file.
# Secrets never live in code. That is a project rule.

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

from services.ingest.schema import SchemaEventIn

# Load the .env file from the project root folder.
# This file lives in services/ingest, so the project
# root is two folders up from here.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

# Build the database address from the .env values.
# Shape: postgresql+psycopg://user:password@host:port/database
DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_NAME = os.getenv("POSTGRES_DB")
DATABASE_URL = (
    f"postgresql+psycopg://{DB_USER}:{DB_PASSWORD}"
    f"@localhost:5433/{DB_NAME}"
)

# The engine is the connection manager for the database.
# It opens a connection when a function here needs one.
engine = create_engine(DATABASE_URL)


def save_event(event: SchemaEventIn) -> int:
    # Save one validated event into the events table and
    # return the new row id that PostgreSQL assigned.
    # The SQL uses named placeholders like :host.
    # SQLAlchemy fills them in safely, so text inside an
    # event can never change the SQL itself. That safety
    # method is called parameterized queries, and it is
    # what stops SQL injection attacks.
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

# Search the events table.
# Every filter is optional. A filter left as None is not used.
# Returns a list of rows, each row as a dictionary.
def search_events(source=None, event_type=None, username=None,
                  source_ip=None, limit=100):
    sql = ("SELECT id, event_time, host, source, event_type, username, "
           "source_ip, outcome, raw, received_at FROM events")
    conditions = []
    values = {}

    # Build only the conditions the caller actually asked for.
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

    # engine.connect is for reading. engine.begin in save_event is for writing.
    with engine.connect() as connection:
        rows = connection.execute(text(sql), values).mappings().all()

    return [dict(row) for row in rows]


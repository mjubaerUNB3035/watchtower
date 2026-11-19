# services/scanner/database.py
# stores scan results in postgresql

import json
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv()

DATABASE_URL = (
    "postgresql+psycopg://"
    + os.getenv("POSTGRES_USER")
    + ":"
    + os.getenv("POSTGRES_PASSWORD")
    + "@localhost:5433/"
    + os.getenv("POSTGRES_DB")
)

engine = create_engine(DATABASE_URL)


# create the scan_results table if it is not there yet
def create_table():
    sql = """
        CREATE TABLE IF NOT EXISTS scan_results (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            host TEXT NOT NULL,
            open_ports JSONB NOT NULL,
            scanned_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """
    with engine.begin() as conn:
        conn.execute(text(sql))


# save one target result and return its new id
def save_result(host, open_ports):
    sql = """
        INSERT INTO scan_results (host, open_ports)
        VALUES (:host, CAST(:open_ports AS JSONB))
        RETURNING id
    """
    with engine.begin() as conn:
        row = conn.execute(
            text(sql),
            {"host": host, "open_ports": json.dumps(open_ports)},
        )
        return row.scalar()


# save every result from one full scan
def store_results(results):
    ids = []
    for result in results:
        new_id = save_result(result["host"], result["open_ports"])
        ids.append(new_id)
    return ids

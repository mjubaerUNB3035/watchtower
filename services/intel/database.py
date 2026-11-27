# services/intel/database.py

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

# Engine
engine = create_engine(
    "postgresql+psycopg://"
    + os.environ["POSTGRES_USER"]
    + ":"
    + os.environ["POSTGRES_PASSWORD"]
    + "@localhost:5433/"
    + os.environ["POSTGRES_DB"]
)


# Create table
def create_table():
    with engine.begin() as conn:
        conn.execute(
            text("""
                CREATE TABLE IF NOT EXISTS intel_cache (
                    ip TEXT PRIMARY KEY,
                    score INTEGER,
                    reports INTEGER,
                    country TEXT,
                    isp TEXT,
                    checked_at TIMESTAMPTZ DEFAULT now()
                )
            """)
        )


# Save intel
def save_intel(record):
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO intel_cache (ip, score, reports, country, isp, checked_at)
                VALUES (:ip, :score, :reports, :country, :isp, now())
                ON CONFLICT (ip) DO UPDATE SET
                    score = EXCLUDED.score,
                    reports = EXCLUDED.reports,
                    country = EXCLUDED.country,
                    isp = EXCLUDED.isp,
                    checked_at = now()
            """),
            record,
        )


# Get intel
def get_intel(ip):
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT ip, score, reports, country, isp, checked_at FROM intel_cache WHERE ip = :ip"),
            {"ip": ip},
        ).mappings().first()
    if row is None:
        return None
    return dict(row)
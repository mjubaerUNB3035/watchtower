# database.py

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


# Create table
def create_table():
    sql = text(
        "CREATE TABLE IF NOT EXISTS phishing_reports ("
        "id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "
        "sender TEXT NOT NULL, "
        "sender_name TEXT, "
        "subject TEXT NOT NULL, "
        "links JSONB NOT NULL, "
        "attachments JSONB NOT NULL, "
        "findings JSONB NOT NULL, "
        "verdict TEXT, "
        "confidence INTEGER, "
        "summary TEXT, "
        "status TEXT NOT NULL DEFAULT 'new', "
        "created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
        ")"
    )
    alter = text(
        "ALTER TABLE phishing_reports "
        "ADD COLUMN IF NOT EXISTS message_id TEXT"
    )
    with engine.begin() as conn:
        conn.execute(sql)
        conn.execute(alter)


# Save report
def save_report(email, findings):
    sql = text(
        "INSERT INTO phishing_reports "
        "(sender, sender_name, subject, links, attachments, findings, message_id) "
        "VALUES (:sender, :sender_name, :subject, "
        "CAST(:links AS JSONB), CAST(:attachments AS JSONB), "
        "CAST(:findings AS JSONB), :message_id) "
        "RETURNING id"
    )
    values = {
        "sender": email["sender"],
        "sender_name": email.get("sender_name", ""),
        "subject": email["subject"],
        "links": json.dumps(email["links"]),
        "attachments": json.dumps(email["attachments"]),
        "findings": json.dumps(findings),
        "message_id": email.get("message_id", ""),
    }
    with engine.begin() as conn:
        row = conn.execute(sql, values).fetchone()
    return row[0]


# List reports
def list_reports():
    sql = text("SELECT * FROM phishing_reports ORDER BY id")
    with engine.connect() as conn:
        rows = conn.execute(sql).mappings()
        reports = []
        for row in rows:
            reports.append(dict(row))
    return reports


# Report exists
def report_exists(message_id):
    sql = text(
        "SELECT COUNT(*) FROM phishing_reports "
        "WHERE message_id = :message_id"
    )
    with engine.connect() as conn:
        count = conn.execute(sql, {"message_id": message_id}).scalar()
    return count > 0

# New reports
def get_new_reports():
    sql = text(
        "SELECT * FROM phishing_reports "
        "WHERE status = 'new' ORDER BY id"
    )
    with engine.connect() as conn:
        rows = conn.execute(sql).mappings()
        reports = []
        for row in rows:
            reports.append(dict(row))
    return reports


# Save verdict
def save_verdict(report_id, verdict, confidence, summary):
    sql = text(
        "UPDATE phishing_reports "
        "SET verdict = :verdict, confidence = :confidence, "
        "summary = :summary, status = 'judged' "
        "WHERE id = :report_id"
    )
    values = {
        "report_id": report_id,
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
    }
    with engine.begin() as conn:
        conn.execute(sql, values)

# Save recheck
def save_recheck(report_id, findings):
    with engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE phishing_reports
                SET findings = :findings,
                    verdict = NULL,
                    confidence = NULL,
                    summary = NULL,
                    status = 'new'
                WHERE id = :report_id
            """),
            {"findings": json.dumps(findings), "report_id": report_id},
        )

# Create blocked table
def create_blocked_table():
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS blocked_senders (
                id SERIAL PRIMARY KEY,
                sender TEXT UNIQUE NOT NULL
            )
        """))


# Add blocked sender
def add_blocked_sender(sender):
    create_blocked_table()
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO blocked_senders (sender) VALUES (:sender) "
                 "ON CONFLICT (sender) DO NOTHING"),
            {"sender": sender.strip().lower()},
        )


# Get blocked List senders
def get_blocked_senders():
    create_blocked_table()
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT sender FROM blocked_senders ORDER BY sender")
        ).fetchall()
    senders = []
    for row in rows:
        senders.append(row[0])
    return senders
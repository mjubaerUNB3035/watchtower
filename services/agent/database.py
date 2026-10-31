# services/agent/database.py
# Database access for the triage agent.
# Agent reads alerts - evidence events - writes verdicts.

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

# Load .env file
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

DATABASE_URL = (
    f"postgresql+psycopg://{os.getenv('POSTGRES_USER')}:"
    f"{os.getenv('POSTGRES_PASSWORD')}@localhost:5433/"
    f"{os.getenv('POSTGRES_DB')}"
)

engine = create_engine(DATABASE_URL)


def get_alerts_to_triage():
    # New marked alerts
    # Duplication Prevented
    sql = """
        SELECT id, created_at, rule_name, severity, mitre_technique, host,
               source_ip, username, event_count, window_start, window_end,
               event_ids, status
        FROM alerts
        WHERE status = 'new'
          AND id NOT IN (SELECT alert_id FROM triage_verdicts)
        ORDER BY id
    """
    with engine.connect() as connection:
        rows = connection.execute(text(sql)).mappings().all()
    return [dict(row) for row in rows]


def get_events(event_ids):
    # The evidence events form alert
    # Order by id.
    sql = """
        SELECT id, event_time, host, source, event_type, username,
               source_ip, outcome, raw
        FROM events
        WHERE id = ANY(CAST(:event_ids AS BIGINT[]))
        ORDER BY id
    """
    with engine.connect() as connection:
        rows = connection.execute(
            text(sql), {"event_ids": list(event_ids)}
        ).mappings().all()
    return [dict(row) for row in rows]


def save_verdict(alert_id, verdict, model):
    # Insert one verdict row and return its new id.
    # created_at and status are filled by the table defaults (now, pending).
    sql = """
        INSERT INTO triage_verdicts
            (alert_id, verdict, confidence, summary,
             recommended_action, model)
        VALUES
            (:alert_id, :verdict, :confidence, :summary,
             :recommended_action, :model)
        RETURNING id
    """
    values = {
        "alert_id": alert_id,
        "verdict": verdict["verdict"],
        "confidence": verdict.get("confidence"),
        "summary": verdict["summary"],
        "recommended_action": verdict.get("recommended_action"),
        "model": model,
    }
    with engine.begin() as connection:
        return connection.execute(text(sql), values).scalar_one()


def get_pending_verdicts():
    # Pending verdicts from triage_verdicts, each with its alerts row joined.
    sql = """
        SELECT v.id AS verdict_id, v.alert_id, a.rule_name,
               a.source_ip, a.username, a.event_count,
               v.verdict, v.confidence, v.summary,
               v.recommended_action
        FROM triage_verdicts v
        JOIN alerts a ON a.id = v.alert_id
        WHERE v.status = 'pending'
        ORDER BY v.id
    """
    with engine.connect() as connection:
        rows = connection.execute(text(sql)).mappings().all()
    return [dict(row) for row in rows]


def review_verdict(verdict_id, decision, human_verdict=None):
    # approved -> status approved. corrected -> human word stored.
    # The pending guard means a verdict can be reviewed only once.
    if decision == "approved":
        sql = """
            UPDATE triage_verdicts
            SET status = 'approved', reviewed_at = now()
            WHERE id = :verdict_id AND status = 'pending'
            RETURNING id
        """
        values = {"verdict_id": verdict_id}
    else:
        sql = """
            UPDATE triage_verdicts
            SET status = 'corrected',
                human_verdict = :human_verdict,
                reviewed_at = now()
            WHERE id = :verdict_id AND status = 'pending'
            RETURNING id
        """
        values = {"verdict_id": verdict_id,
                  "human_verdict": human_verdict}
    with engine.begin() as connection:
        return connection.execute(
            text(sql), values
        ).scalar_one_or_none()

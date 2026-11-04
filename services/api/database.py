# services/api/database.py
# Read-only queries for the dashboard API.
# One engine, like every other service. Nothing here writes;
# review writes go through the agent's review_verdict function.

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

ALERT_COLUMNS = """
    a.id, a.created_at, a.rule_name, a.severity,
    a.mitre_technique, a.host, a.source_ip, a.username,
    a.event_count, a.window_start, a.window_end, a.event_ids,
    a.status AS alert_status,
    v.id AS verdict_id, v.verdict, v.confidence, v.summary,
    v.recommended_action, v.model,
    v.status AS review_status, v.human_verdict, v.reviewed_at
"""

LATEST_VERDICT = """
    LEFT JOIN LATERAL (
        SELECT * FROM triage_verdicts
        WHERE alert_id = a.id
        ORDER BY id DESC
        LIMIT 1
    ) v ON TRUE
"""


def list_alerts():
    # Every alert, each with its latest verdict beside it.
    sql = f"""
        SELECT {ALERT_COLUMNS}
        FROM alerts a
        {LATEST_VERDICT}
        ORDER BY a.id
    """
    with engine.connect() as connection:
        rows = connection.execute(text(sql)).mappings().all()
    return [dict(row) for row in rows]


def get_alert_detail(alert_id):
    # One alert, its latest verdict, and its evidence events.
    sql = f"""
        SELECT {ALERT_COLUMNS}
        FROM alerts a
        {LATEST_VERDICT}
        WHERE a.id = :alert_id
    """
    with engine.connect() as connection:
        row = connection.execute(
            text(sql), {"alert_id": alert_id}
        ).mappings().one_or_none()
    if row is None:
        return None
    alert = dict(row)
    events_sql = """
        SELECT id, event_time, host, source, event_type, username,
               source_ip, outcome, raw
        FROM events
        WHERE id = ANY(CAST(:event_ids AS BIGINT[]))
        ORDER BY id
    """
    with engine.connect() as connection:
        rows = connection.execute(
            text(events_sql), {"event_ids": list(alert["event_ids"])}
        ).mappings().all()
    alert["events"] = [dict(r) for r in rows]
    return alert


#Overview
def overview_counts():
    # The numbers on the Overview page cards.
    counts = {}
    simple = {
        "events": "SELECT COUNT(*) FROM events",
        "alerts": "SELECT COUNT(*) FROM alerts",
        "pending_reviews":
            "SELECT COUNT(*) FROM triage_verdicts "
            "WHERE status = 'pending'",
        "corrections":
            "SELECT COUNT(*) FROM triage_verdicts "
            "WHERE status = 'corrected'",
    }
    with engine.connect() as connection:
        for key, sql in simple.items():
            counts[key] = connection.execute(text(sql)).scalar_one()
        rows = connection.execute(text("""
            SELECT COALESCE(human_verdict, verdict) AS final_verdict,
                   COUNT(*) AS n
            FROM triage_verdicts
            WHERE status IN ('approved', 'corrected')
            GROUP BY final_verdict
        """)).mappings().all()
    counts["final_verdicts"] = {
        row["final_verdict"]: row["n"] for row in rows
    }
    return counts

# --- Incidents ---

def final_verdict_of(alert):
    return alert.get("human_verdict") or alert.get("verdict")


def incident_eligible(alert):
    reviewed = alert.get("review_status") in ("approved", "corrected")
    return reviewed and final_verdict_of(alert) == "true_positive"


def incident_title(alert):
    return f"{alert['rule_name']} from {alert['source_ip']}"


def get_incident_for_alert(alert_id):
    sql = text(
        "SELECT id, alert_id, created_at, title, status, notes, closed_at "
        "FROM incidents WHERE alert_id = :alert_id"
    )
    with engine.connect() as conn:
        row = conn.execute(sql, {"alert_id": alert_id}).mappings().first()
    return dict(row) if row else None


def create_incident(alert):
    sql = text(
        "INSERT INTO incidents (alert_id, title) VALUES (:alert_id, :title) "
        "RETURNING id, alert_id, created_at, title, status, notes, closed_at"
    )
    params = {"alert_id": alert["id"], "title": incident_title(alert)}
    with engine.begin() as conn:
        row = conn.execute(sql, params).mappings().first()
    return dict(row)


def list_incidents():
    sql = text(
        "SELECT i.id, i.alert_id, i.created_at, i.title, i.status, "
        "i.notes, i.closed_at, a.rule_name, a.severity, a.source_ip "
        "FROM incidents i JOIN alerts a ON a.id = i.alert_id ORDER BY i.id"
    )
    with engine.connect() as conn:
        rows = conn.execute(sql).mappings().all()
    return [dict(row) for row in rows]


def get_incident(incident_id):
    sql = text(
        "SELECT id, alert_id, created_at, title, status, notes, closed_at "
        "FROM incidents WHERE id = :incident_id"
    )
    with engine.connect() as conn:
        row = conn.execute(sql, {"incident_id": incident_id}).mappings().first()
    return dict(row) if row else None


def update_incident(incident_id, status, notes):
    sql = text(
        "UPDATE incidents SET status = :status, notes = :notes, "
        "closed_at = CASE WHEN :status = 'closed' THEN now() "
        "WHEN :status = 'open' THEN NULL ELSE closed_at END "
        "WHERE id = :incident_id RETURNING id"
    )
    params = {"incident_id": incident_id, "status": status, "notes": notes}
    with engine.begin() as conn:
        found = conn.execute(sql, params).scalar_one_or_none()
    return found

# --- Shift log ---

def shift_summary(hours):
    since_sql = "now() - INTERVAL '1 hour' * :hours"
    params = {"hours": hours}
    with engine.connect() as conn:
        events_count = conn.execute(
            text(f"SELECT COUNT(*) FROM events WHERE event_time >= {since_sql}"),
            params,
        ).scalar_one()
        alerts = conn.execute(
            text(
                "SELECT a.id, a.created_at, a.rule_name, a.severity, "
                "a.source_ip, a.event_count, v.verdict, v.human_verdict, "
                "v.status AS review_status FROM alerts a "
                "LEFT JOIN LATERAL ("
                "SELECT verdict, human_verdict, status FROM triage_verdicts "
                "WHERE alert_id = a.id ORDER BY id DESC LIMIT 1"
                ") v ON true "
                f"WHERE a.created_at >= {since_sql} ORDER BY a.id"
            ),
            params,
        ).mappings().all()
        reviews = conn.execute(
            text(
                "SELECT id, alert_id, verdict, human_verdict, status, "
                "reviewed_at FROM triage_verdicts "
                f"WHERE reviewed_at >= {since_sql} ORDER BY id"
            ),
            params,
        ).mappings().all()
        incidents = conn.execute(
            text(
                "SELECT id, alert_id, title, status, created_at "
                f"FROM incidents WHERE created_at >= {since_sql} ORDER BY id"
            ),
            params,
        ).mappings().all()
        open_incidents = conn.execute(
            text("SELECT COUNT(*) FROM incidents WHERE status <> 'closed'")
        ).scalar_one()
        pending = conn.execute(
            text(
                "SELECT COUNT(*) FROM triage_verdicts "
                "WHERE status = 'pending'"
            )
        ).scalar_one()
    return {
        "hours": hours,
        "events_in_window": events_count,
        "new_alerts": [dict(r) for r in alerts],
        "reviews_done": [dict(r) for r in reviews],
        "incidents_opened": [dict(r) for r in incidents],
        "open_incidents": open_incidents,
        "pending_reviews": pending,
    }
# --- Hosts and users ---

def list_hosts():
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT host, COUNT(*) AS events, "
                "COUNT(*) FILTER (WHERE outcome = 'failure') AS failures, "
                "COUNT(*) FILTER (WHERE outcome = 'success') AS successes, "
                "COUNT(DISTINCT username) AS users, "
                "COUNT(DISTINCT source_ip) AS source_ips, "
                "MIN(event_time) AS first_seen, MAX(event_time) AS last_seen "
                "FROM events GROUP BY host ORDER BY host"
            )
        ).mappings().all()
    return [dict(r) for r in rows]


def list_users():
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT username, COUNT(*) AS events, "
                "COUNT(*) FILTER (WHERE outcome = 'failure') AS failures, "
                "COUNT(*) FILTER (WHERE outcome = 'success') AS successes, "
                "COUNT(DISTINCT source_ip) AS source_ips, "
                "COUNT(DISTINCT host) AS hosts, "
                "MIN(event_time) AS first_seen, MAX(event_time) AS last_seen "
                "FROM events WHERE username IS NOT NULL "
                "GROUP BY username ORDER BY username"
            )
        ).mappings().all()
    return [dict(r) for r in rows]


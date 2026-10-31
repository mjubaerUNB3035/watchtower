# services/agent/memory.py
# Correction memory: what the human reviewer decided before.
# Past corrections for the same rule are added to the prompt,
# so the model follows the reviewer's earlier rulings.

from sqlalchemy import text

from services.agent.database import engine


def past_corrections(rule_name):
    # Human corrections for one rule -> text lines for the prompt.
    sql = """
        SELECT v.verdict AS model_verdict,
               v.human_verdict AS human_verdict,
               a.source_ip AS source_ip
        FROM triage_verdicts v
        JOIN alerts a ON a.id = v.alert_id
        WHERE v.status = 'corrected'
          AND a.rule_name = :rule_name
        ORDER BY v.id
    """
    with engine.connect() as connection:
        rows = connection.execute(
            text(sql), {"rule_name": rule_name}
        ).mappings().all()
    lines = []
    for row in rows:
        lines.append(
            f"human correction: on a past {rule_name} alert from "
            f"{row['source_ip']} the model said "
            f"{row['model_verdict']}, the reviewer corrected it "
            f"to {row['human_verdict']}"
        )
    return lines

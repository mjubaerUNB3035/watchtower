# services/agent/evaluate.py
# Evaluation run for the triage agent.
# Runs the full chain on every alert and prints the verdicts
# WITHOUT saving anything. Reviewed verdicts stay final.
# Known correct answers for the current 4 alerts are below.

from sqlalchemy import text

from services.agent.brain import think
from services.agent.database import engine, get_events
from services.agent.prompts import build_triage_prompt
from services.agent.tools import alert_facts, gather_intel

EXPECTED = {1: "true_positive", 2: "true_positive",
            3: "true_positive", 4: "true_positive"}


def get_all_alerts():
    # Every alert in the table, reviewed or not, oldest first.
    sql = "SELECT * FROM alerts ORDER BY id"
    with engine.connect() as connection:
        rows = connection.execute(text(sql)).mappings().all()
    return [dict(row) for row in rows]


def run_all():
    correct = 0
    for alert in get_all_alerts():
        events = get_events(alert["event_ids"])
        intel = gather_intel(alert["source_ip"]) + alert_facts(alert, events)
        prompt_text = build_triage_prompt(alert, events, intel)
        verdict = think(prompt_text)
        expected = EXPECTED.get(alert["id"], "?")
        mark = "OK" if verdict["verdict"] == expected else "MISS"
        if verdict["verdict"] == expected:
            correct += 1
        print(
            f"alert {alert['id']} {alert['rule_name']}: "
            f"{verdict['verdict']} (confidence "
            f"{verdict.get('confidence')}), expected {expected} [{mark}]"
        )
    print(f"score: {correct} of {len(EXPECTED)} correct")


if __name__ == "__main__":
    run_all()

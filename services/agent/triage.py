# services/agent/triage.py
# triage runner, saves one pending verdict per alert

from services.agent.brain import MODEL, think            # model name, think()
from services.agent.database import (get_alerts_to_triage, get_events,
                                     save_verdict)       # alert queue, events, save verdict
from services.agent.prompts import build_triage_prompt   # build the prompt text
from services.agent.tools import gather_intel            # ip lookups
from services.agent.tools import alert_facts, gather_intel  # alert facts, ip lookups
from services.agent.memory import past_corrections       # past corrections for the prompt


def triage_alert(alert):                                 # chain for one alert
    # run the full chain for one alert, save its verdict
    events = get_events(alert["event_ids"])              # evidence rows for the alert
    intel = gather_intel(alert["source_ip"]) + alert_facts(alert, events) + past_corrections(alert["rule_name"]) # intel, facts, past corrections
    intel = gather_intel(alert["source_ip"]) + alert_facts(alert, events) # intel, facts
    prompt_text = build_triage_prompt(alert, events, intel)  # build the prompt text
    verdict = think(prompt_text)                         # ollama verdict dict
    verdict_id = save_verdict(alert["id"], verdict, MODEL)   # save verdict, returns new id
    return verdict_id, verdict


def run_all():                                           # loop the whole queue
    # triage every alert in the queue, oldest first
    alerts = get_alerts_to_triage()                      # alerts waiting for triage
    if not alerts:
        print("no alerts waiting for triage")
        return
    for alert in alerts:
        print(
            f"triaging alert {alert['id']} {alert['rule_name']} "
            f"{alert['source_ip']} ..."
        )
        verdict_id, verdict = triage_alert(alert)        # chain for this alert
        print(
            f"verdict {verdict_id} saved for alert {alert['id']}: "
            f"{verdict['verdict']} "
            f"(confidence {verdict.get('confidence')}), pending review"
        )
    print(f"triaged {len(alerts)} alert(s)")


if __name__ == "__main__":
    run_all()                                            # entry point

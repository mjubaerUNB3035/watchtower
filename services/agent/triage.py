# services/agent/triage.py
# The triage agent runner.
# For every alert waiting in the queue it runs the full chain:
# evidence, intel, prompt, brain, save the verdict as pending.
# The agent writes verdicts only. A human reviews every one.

from services.agent.brain import MODEL, think            # brain.py: model name, thinker
from services.agent.database import (get_alerts_to_triage, get_events,
                                     save_verdict)       # database.py: queue, evidence, save
from services.agent.prompts import build_triage_prompt   # prompts.py: packs the text
from services.agent.tools import gather_intel            # tools.py: IP lookups
from services.agent.tools import alert_facts, gather_intel
from services.agent.memory import past_corrections


def triage_alert(alert):                                 # this file: chain for one alert
    # Run the whole chain for one alert and save its verdict.
    # Returns the new verdict id and the verdict dict.
    events = get_events(alert["event_ids"])              # database.py: fetch evidence rows
    intel = gather_intel(alert["source_ip"]) + alert_facts(alert, events) + past_corrections(alert["rule_name"]) # tools.py: 2 intel lines for the IP memory.py: past corrections for this rule
    intel = gather_intel(alert["source_ip"]) + alert_facts(alert, events) #tools.py
    prompt_text = build_triage_prompt(alert, events, intel)  # prompts.py: pack into one text
    verdict = think(prompt_text)                         # brain.py: Ollama returns verdict dict
    verdict_id = save_verdict(alert["id"], verdict, MODEL)   # database.py: insert, return new id
    return verdict_id, verdict


def run_all():                                           # this file: loop the whole queue
    # Triage every alert in the queue, oldest first.
    alerts = get_alerts_to_triage()                      # database.py: waiting alerts list
    if not alerts:
        print("no alerts waiting for triage")
        return
    for alert in alerts:
        print(
            f"triaging alert {alert['id']} {alert['rule_name']} "
            f"{alert['source_ip']} ..."
        )
        verdict_id, verdict = triage_alert(alert)        # this file: chain for this one alert
        print(
            f"verdict {verdict_id} saved for alert {alert['id']}: "
            f"{verdict['verdict']} "
            f"(confidence {verdict.get('confidence')}), pending review"
        )
    print(f"triaged {len(alerts)} alert(s)")


if __name__ == "__main__":
    run_all()                                            # this file: start

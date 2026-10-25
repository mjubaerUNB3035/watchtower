# WatchTower detection engine.
#
# How a run flows:
#   1. fetch_events asks the ingest API (GET /events) for one event_type.
#      JSON turns datetimes into text, so each event_time is parsed back
#      into a real datetime with datetime.fromisoformat.
#   2. find_alerts groups the events by the rule's group_by field (for the
#      login rules: one group per source_ip), sorts each group by time,
#      then slides a window: start at each event in turn and score the
#      events that follow it inside window_minutes. The score is the event
#      count, or, when the rule has count_distinct, the number of distinct
#      values of that field. The first start that reaches the threshold
#      builds one alert dict for that group.
#   3. run_all runs every rule in RULES, skips alerts that are already
#      saved (alert_exists, same rule name and same event_ids), and saves
#      each new alert with save_alert. The alert dict keys match the
#      save_alert placeholders, so re-running the engine is safe.

from datetime import datetime, timedelta

import httpx

from services.detection.database import alert_exists, save_alert
from services.detection.rules import RULES

API_URL = "http://127.0.0.1:8000/events"


def fetch_events(event_type: str) -> list[dict]:
    """Ask the ingest API for all events of one event_type."""
    response = httpx.get(API_URL, params={"event_type": event_type})
    response.raise_for_status()
    events = response.json()
    for event in events:
        event["event_time"] = datetime.fromisoformat(event["event_time"])
    return events


def find_alerts(rule: dict, events: list[dict]) -> list[dict]:
    """Run one rule over events and return the alert dicts it fires."""
    groups: dict[str, list[dict]] = {}
    for event in events:
        key = event[rule["group_by"]]
        groups.setdefault(key, []).append(event)

    alerts = []
    window_size = timedelta(minutes=rule["window_minutes"])
    for group in groups.values():
        group.sort(key=lambda e: e["event_time"])
        for i, start in enumerate(group):
            members = [
                e for e in group[i:]
                if e["event_time"] - start["event_time"] <= window_size
            ]
            if "count_distinct" in rule:
                score = len({e[rule["count_distinct"]] for e in members})
            else:
                score = len(members)
            if score >= rule["threshold"]:
                usernames = {e["username"] for e in members}
                alerts.append(
                    {
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "mitre_technique": rule["mitre_technique"],
                        "host": members[0]["host"],
                        "source_ip": members[0]["source_ip"],
                        "username": usernames.pop() if len(usernames) == 1 else None,
                        "event_count": len(members),
                        "window_start": members[0]["event_time"],
                        "window_end": members[-1]["event_time"],
                        "event_ids": [e["id"] for e in members],
                    }
                )
                break
    return alerts


def run_all() -> None:
    """Run every rule, save new alerts, skip ones already saved."""
    for rule in RULES:
        events = fetch_events(rule["event_type"])
        alerts = find_alerts(rule, events)
        for alert in alerts:
            if alert_exists(alert["rule_name"], alert["event_ids"]):
                print(f"skip {alert['rule_name']} {alert['source_ip']} (already alerted)")
                continue
            new_id = save_alert(alert)
            print(f"alert {new_id} {alert['rule_name']} {alert['source_ip']} count {alert['event_count']}")
        print(f"{rule['name']}: {len(alerts)} alert(s)")





if __name__ == "__main__":
    run_all()

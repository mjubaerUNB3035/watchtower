# services/detection/engine.py
# detection engine: fetch events, run rules, save alerts

from datetime import datetime, timedelta

import httpx

from services.detection.database import alert_exists, save_alert
from services.detection.rules import RULES

API_URL = "http://127.0.0.1:8000/events"


def fetch_events(event_type: str) -> list[dict]:
    # events of one type from the ingest api, event_time parsed back
    response = httpx.get(API_URL, params={"event_type": event_type})
    response.raise_for_status()
    events = response.json()
    for event in events:
        event["event_time"] = datetime.fromisoformat(event["event_time"])
    return events


def find_alerts(rule: dict, events: list[dict]) -> list[dict]:
    # run one rule over grouped events, return the fired alert dicts
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
    # run every rule, save new alerts, skip ones already saved
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

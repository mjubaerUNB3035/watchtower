# Tests for the detection engine's find_alerts function.
#
# find_alerts is pure: it takes a rule dict and a list of event dicts and
# returns alert dicts. No database, no API. The events here are built by
# make_event with only the fields find_alerts actually reads, and the
# rules are the real ones from services.detection.rules.

from datetime import datetime, timedelta, timezone

from services.detection.engine import find_alerts
from services.detection.rules import RULES

BASE = datetime(2026, 10, 24, 14, 0, tzinfo=timezone.utc)


def make_event(event_id, minutes, username="md",
               source_ip="203.0.113.45", event_type="login_failed"):
    return {
        "id": event_id,
        "event_time": BASE + timedelta(minutes=minutes),
        "host": "watchtower-linux",
        "source": "linux_auth",
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "outcome": "failure",
        "raw": "test event",
    }


def rule_named(name):
    return next(r for r in RULES if r["name"] == name)


def test_brute_force_fires_at_threshold():
    rule = rule_named("brute_force_login")
    events = [make_event(i, i) for i in range(5)]
    alerts = find_alerts(rule, events)
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 5
    assert alerts[0]["username"] == "md"
    assert alerts[0]["event_ids"] == [0, 1, 2, 3, 4]


def test_brute_force_quiet_below_threshold():
    rule = rule_named("brute_force_login")
    events = [make_event(i, i) for i in range(4)]
    assert find_alerts(rule, events) == []


def test_brute_force_quiet_outside_window():
    rule = rule_named("brute_force_login")
    events = [make_event(i, i * 30) for i in range(5)]
    assert find_alerts(rule, events) == []


def test_password_spraying_fires_on_distinct_usernames():
    rule = rule_named("password_spraying")
    users = ["root", "admin", "oracle", "ubuntu"]
    events = [
        make_event(i, i, username=u, source_ip="198.51.100.99")
        for i, u in enumerate(users)
    ]
    alerts = find_alerts(rule, events)
    assert len(alerts) == 1
    assert alerts[0]["username"] is None
    assert alerts[0]["event_count"] == 4


def test_password_spraying_quiet_for_one_username():
    rule = rule_named("password_spraying")
    events = [
        make_event(i, i, source_ip="198.51.100.99") for i in range(4)
    ]
    assert find_alerts(rule, events) == []


def test_web_scanning_fires():
    rule = rule_named("web_scanning")
    events = [
        make_event(i, i, username=None, source_ip="198.51.100.23",
                   event_type="http_client_error")
        for i in range(5)
    ]
    alerts = find_alerts(rule, events)
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "web_scanning"

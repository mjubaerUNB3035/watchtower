# tests/test_agent.py
# Unit tests for the triage agent's pure parts.
# No database, no network, no model: fake dicts in, text out.

from datetime import datetime, timedelta, timezone

import pytest

from services.agent.brain import parse_verdict
from services.agent.prompts import build_triage_prompt
from services.agent.tools import alert_facts

BASE = datetime(2026, 10, 31, 17, 20, 5, tzinfo=timezone.utc)

ALERT = {
    "rule_name": "brute_force_login",
    "severity": "high",
    "mitre_technique": "T1110",
    "host": "watchtower-linux",
    "source_ip": "198.51.100.50",
    "username": "root",
    "event_count": 6,
    "window_start": BASE,
    "window_end": BASE + timedelta(minutes=2, seconds=30),
}


def make_event(minutes=0, outcome="failure", username="root"):
    # One fake event dict, the same shape get_events returns.
    return {
        "event_time": BASE + timedelta(minutes=minutes),
        "event_type": "login_failed",
        "username": username,
        "source_ip": "198.51.100.50",
        "outcome": outcome,
        "raw": "Failed password",
    }


# parse_verdict: the brain's checker for the model answer

def test_parse_verdict_accepts_good_answer():
    text = ('{"verdict": "true_positive", "confidence": 90, '
            '"summary": "Six failures from one IP."}')
    result = parse_verdict(text)
    assert result["verdict"] == "true_positive"
    assert result["confidence"] == 90


def test_parse_verdict_rejects_bad_word():
    text = '{"verdict": "maybe", "summary": "Not sure."}'
    with pytest.raises(ValueError):
        parse_verdict(text)


def test_parse_verdict_rejects_missing_summary():
    text = '{"verdict": "true_positive", "confidence": 90}'
    with pytest.raises(ValueError):
        parse_verdict(text)


def test_parse_verdict_rejects_not_json():
    with pytest.raises(ValueError):
        parse_verdict("the model said something else")


# alert_facts: facts counted by code, not by the model

def test_facts_counts_failures():
    alert = dict(ALERT, source_ip="8.8.8.8")
    events = [make_event(minutes=i) for i in range(6)]
    lines = alert_facts(alert, events)



def test_facts_success_after_failure():
    events = [make_event(minutes=0),
              make_event(minutes=1, outcome="success")]
    lines = alert_facts(ALERT, events)
    assert lines[1].endswith(": yes")


def test_facts_counts_distinct_usernames():
    events = [make_event(username="root"),
              make_event(username="admin"),
              make_event(username="root")]
    lines = alert_facts(ALERT, events)
    assert "2 (admin, root)" in lines[2]


def test_facts_private_source():
    alert = dict(ALERT, source_ip="8.8.8.8")
    events = [make_event(minutes=i) for i in range(6)]
    lines = alert_facts(alert, events)


# build_triage_prompt: the packing of alert, events, intel

def test_prompt_packs_all_sections():
    events = [make_event()]
    intel = ["ip_history: test line", "facts: test line"]
    text = build_triage_prompt(ALERT, events, intel)
    assert "brute_force_login" in text
    assert "EVIDENCE EVENTS" in text
    assert "ip_history: test line" in text


def test_prompt_empty_intel_says_none():
    text = build_triage_prompt(ALERT, [make_event()], [])
    assert text.split("INTEL")[1].strip() == "none"

# tests for the dashboard gateway helpers

from services.api.database import (
    final_verdict_of,
    incident_eligible,
    incident_title,
)


def test_final_verdict_prefers_human_word():
    alert = {"verdict": "false_positive", "human_verdict": "true_positive"}
    assert final_verdict_of(alert) == "true_positive"


def test_final_verdict_falls_back_to_model_word():
    alert = {"verdict": "true_positive", "human_verdict": None}
    assert final_verdict_of(alert) == "true_positive"


def test_eligible_approved_true_positive():
    alert = {
        "review_status": "approved",
        "verdict": "true_positive",
        "human_verdict": None,
    }
    assert incident_eligible(alert) is True


def test_eligible_corrected_to_true_positive():
    alert = {
        "review_status": "corrected",
        "verdict": "false_positive",
        "human_verdict": "true_positive",
    }
    assert incident_eligible(alert) is True


def test_not_eligible_when_pending():
    alert = {
        "review_status": "pending",
        "verdict": "true_positive",
        "human_verdict": None,
    }
    assert incident_eligible(alert) is False


def test_not_eligible_when_false_positive():
    alert = {
        "review_status": "approved",
        "verdict": "false_positive",
        "human_verdict": None,
    }
    assert incident_eligible(alert) is False


def test_incident_title_uses_rule_and_ip():
    alert = {"rule_name": "brute_force_login", "source_ip": "198.51.100.77"}
    assert incident_title(alert) == "brute_force_login from 198.51.100.77"

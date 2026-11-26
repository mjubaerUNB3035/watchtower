# services/phishing/recheck.py

from services.phishing.checks import run_checks
from services.phishing.database import get_blocked_senders, list_reports, save_recheck
from services.phishing.mailbox import fetch_by_message_id


# Recheck one
def recheck_one(report, blocked):
    if not report["message_id"]:
        print(report["id"], "no message id, skipped")
        return 0
    try:
        email = fetch_by_message_id(report["message_id"])
    except Exception as error:
        print(report["id"], "fetch failed:", error)
        return 0
    if email is None:
        print(report["id"], "email not found, skipped")
        return 0
    findings = run_checks(email, blocked)
    save_recheck(report["id"], findings)
    print(report["id"], email["sender"], "findings:", len(findings))
    return 1

# Recheck all
def recheck_all():
    blocked = get_blocked_senders()
    done = 0
    for report in list_reports():
        done += recheck_one(report, blocked)
    print("rechecked:", done)


if __name__ == "__main__":
    recheck_all()
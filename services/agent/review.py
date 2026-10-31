# services/agent/review.py
# The human review step (SOC 2). Lists every pending verdict,
# shows the alert facts beside the model verdict, and records
# the human decision: approved, or corrected with the right word.
# Run: python -m services.agent.review

from services.agent.brain import VERDICTS
from services.agent.database import get_pending_verdicts, review_verdict


def show_verdict(v):
    # One pending verdict with the facts it is judged against.
    print(f"verdict {v['verdict_id']} for alert {v['alert_id']}: "
          f"{v['rule_name']}, {v['source_ip']}, "
          f"user {v['username']}, count {v['event_count']}")
    print(f"  model: {v['verdict']} (confidence {v['confidence']})")
    print(f"  summary: {v['summary']}")
    print(f"  action: {v['recommended_action']}")


def ask_decision(v):
    # Ask until the reviewer answers a, c, or s.
    while True:
        answer = input("approve [a], correct [c], skip [s]: ")
        answer = answer.strip().lower()
        if answer in ("a", "c", "s"):
            return answer
        print("type a, c, or s")


def ask_correct_word():
    # Ask until the reviewer types one of the 3 verdict words.
    while True:
        word = input(f"correct verdict {VERDICTS}: ").strip()
        if word in VERDICTS:
            return word
        print("type one of the 3 verdict words exactly")


def run_all():
    pending = get_pending_verdicts()
    if not pending:
        print("no verdicts waiting for review")
        return
    reviewed = 0
    for v in pending:
        show_verdict(v)
        answer = ask_decision(v)
        if answer == "s":
            print(f"verdict {v['verdict_id']} left pending")
            continue
        if answer == "a":
            saved = review_verdict(v["verdict_id"], "approved")
        else:
            word = ask_correct_word()
            saved = review_verdict(v["verdict_id"], "corrected", word)
        if saved is not None:
            reviewed += 1
            print(f"verdict {v['verdict_id']} recorded")
        else:
            print(f"verdict {v['verdict_id']} was not pending, skipped")
    print(f"reviewed {reviewed} verdict(s)")


if __name__ == "__main__":
    run_all()

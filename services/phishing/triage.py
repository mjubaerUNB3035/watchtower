# triage.py

from services.agent.brain import think_phishing
from services.phishing.database import get_new_reports, save_verdict


# Rules
PHISH_SYSTEM_PROMPT = (
    "You are a phishing analyst. Judge one email from the facts given. "
    "Answer with JSON only: "
    "{\"verdict\": \"phishing\" or \"suspicious\" or \"safe\", "
    "\"confidence\": 0 to 100, \"summary\": \"one short reason\"}. "
    "Rules: a sender or link that imitates a brand means phishing. "
    "A dangerous attachment type means phishing. "
    "An IP address link with pressure words in the subject means phishing. "
    "Only pressure words, only a shortener, or only a macro attachment "
    "means suspicious. "
    "Zero findings means safe. "
    "If the facts are unclear, answer needs_more_info as the verdict."
)


# Count by check
def count_by_check(findings):
    counts = {}
    for finding in findings:
        name = finding["check"]
        if name in counts:
            counts[name] += 1
        else:
            counts[name] = 1
    return counts


# Build prompt
def build_phish_prompt(report):
    findings = report["findings"]
    counts = count_by_check(findings)
    lines = []
    lines.append("Sender: " + report["sender"])
    lines.append("Sender name: " + (report["sender_name"] or ""))
    lines.append("Subject: " + report["subject"])
    lines.append("Links: " + str(len(report["links"])))
    for link in report["links"]:
        lines.append("Link: " + link)
    lines.append("Attachments: " + str(len(report["attachments"])))
    for name in report["attachments"]:
        lines.append("Attachment: " + name)
    lines.append("Findings: " + str(len(findings)))
    for name, count in counts.items():
        lines.append("Findings from " + name + ": " + str(count))
    for finding in findings:
        lines.append("Finding: " + finding["detail"])
    return "\n".join(lines)


# Judge one
def judge_report(report):
    prompt = build_phish_prompt(report)
    result = think_phishing(prompt, PHISH_SYSTEM_PROMPT)
    save_verdict(
        report["id"],
        result["verdict"],
        result["confidence"],
        result["summary"],
    )
    return result


# Run triage
def main():
    reports = get_new_reports()
    judged = 0
    for report in reports:
        result = judge_report(report)
        print(report["id"], result["verdict"], result["confidence"])
        judged += 1
    print("judged:", judged)


if __name__ == "__main__":
    main()

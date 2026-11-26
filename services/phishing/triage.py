# triage.py

from services.agent.brain import think_phishing
from services.phishing.database import get_new_reports, save_verdict
from services.phishing.checks import host_of

# Rules
PHISH_SYSTEM_PROMPT = (
    "You are a phishing analyst. Judge one email from the facts given. "
    "Answer with JSON only: "
    "{\"verdict\": \"phishing\" or \"suspicious\" or \"safe\", "
    "\"confidence\": 0 to 100, \"summary\": \"one short reason\"}. "
    "Rules: a finding named fake sender, blocked sender, fake link, dangerous link, "
    "trick link, dangerous attachment, fake attachment, or "
    "failed authentication means phishing. "
    "Only findings named sender brand claim, reply-to mismatch, "
    "hidden link, unsecure link, deep subdomain link, macro attachment, "
    "archive attachment, pressure subject, or money subject "
    "means suspicious. "
    "Zero findings means safe. "
    "If the facts are unclear, answer needs_more_info as the verdict."
    "Use exactly these three keys and no others: "
    "{\"verdict\": \"safe\", \"confidence\": 90, "
    "\"summary\": \"one short reason\"} is the shape. "
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
        lines.append("Link host: " + host_of(link))
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
    if not report["findings"]:
        result = {
            "verdict": "safe",
            "confidence": 100,
            "summary": "No findings from checks.",
        }
        save_verdict(
            report["id"],
            result["verdict"],
            result["confidence"],
            result["summary"],
        )
        return result
    prompt = build_phish_prompt(report)
    result = think_phishing(prompt, PHISH_SYSTEM_PROMPT)
    if result["verdict"] == "needs_more_info" and result["confidence"] == 0:
        return result
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
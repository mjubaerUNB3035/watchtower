# services/scanner/triage.py

from sqlalchemy import text

from services.agent.brain import think_scan
from services.scanner.database import engine

# Rules
SENSITIVE_PORTS = (5432, 5433)

SCAN_SYSTEM_PROMPT = """You are the scan triage analyst for WatchTower.
You judge one machine's latest port scan result.
The facts are counted by code and given to you. Do not invent ports or services.

Decision table:
- A database port open (5432 or 5433) means the database can be reached over the network. Level high.
- A newly open port since the previous scan is a change nobody approved. Level medium or high.
- The Ollama port (11434) open means the local AI server can be reached. Level medium.
- A WatchTower API port open (8000 or 8001) is expected while the platform runs. Level low unless it is newly open.
- No open ports, or no changes and nothing sensitive open, is level low.

Answer with JSON only, in this shape:
{"level": "high", "confidence": 80, "summary": "one short sentence", "recommended_action": "one short action"}
Confidence is a whole number from 0 to 100."""


# Read Scans

# Scanned hosts
def scanned_hosts():
    sql = "SELECT DISTINCT host FROM scan_results ORDER BY host"
    with engine.connect() as conn:
        rows = conn.execute(text(sql)).mappings().all()
    hosts = []
    for row in rows:
        hosts.append(row["host"])
    return hosts


# Last two scans
def last_two_scans(host):
    sql = """
        SELECT open_ports, scanned_at
        FROM scan_results
        WHERE host = :host
        ORDER BY scanned_at DESC
        LIMIT 2
    """
    with engine.connect() as conn:
        rows = conn.execute(text(sql), {"host": host}).mappings().all()
    return rows


# Facts

# Port difference
def port_diff(current, other):
    other_ports = set()
    for item in other:
        other_ports.add(item["port"])
    diff = []
    for item in current:
        if item["port"] not in other_ports:
            diff.append(item)
    return diff


# Sensitive open
def sensitive_open(open_ports):
    found = []
    for item in open_ports:
        if item["port"] in SENSITIVE_PORTS:
            found.append(item)
    return found


# Scan facts
def scan_facts(host):
    rows = last_two_scans(host)
    current = rows[0]["open_ports"]
    facts = {}
    facts["host"] = host
    facts["scanned_at"] = str(rows[0]["scanned_at"])
    facts["open_ports"] = current
    facts["open_count"] = len(current)
    facts["sensitive_open"] = sensitive_open(current)
    if len(rows) > 1:
        previous = rows[1]["open_ports"]
        facts["has_previous"] = True
        facts["new_ports"] = port_diff(current, previous)
        facts["closed_ports"] = port_diff(previous, current)
    else:
        facts["has_previous"] = False
        facts["new_ports"] = []
        facts["closed_ports"] = []
    return facts


# Prompt

# Build prompt
def build_scan_prompt(facts):
    lines = []
    lines.append("Host: " + facts["host"])
    lines.append("Scanned at: " + facts["scanned_at"])
    lines.append("Open ports now: " + str(facts["open_count"]))
    for item in facts["open_ports"]:
        lines.append("  port " + str(item["port"]) + " " + item["service"])
    if facts["has_previous"]:
        lines.append("Newly open since the previous scan: " + str(len(facts["new_ports"])))
        for item in facts["new_ports"]:
            lines.append("  new port " + str(item["port"]) + " " + item["service"])
        lines.append("Closed since the previous scan: " + str(len(facts["closed_ports"])))
        for item in facts["closed_ports"]:
            lines.append("  closed port " + str(item["port"]) + " " + item["service"])
    else:
        lines.append("No previous scan stored for this host.")
    lines.append("Sensitive ports open: " + str(len(facts["sensitive_open"])))
    for item in facts["sensitive_open"]:
        lines.append("  sensitive port " + str(item["port"]) + " " + item["service"])
    return "\n".join(lines)


# Run

# Run triage
def main():
    for host in scanned_hosts():
        facts = scan_facts(host)
        prompt = build_scan_prompt(facts)
        judgment = think_scan(prompt, SCAN_SYSTEM_PROMPT)
        print(host)
        print("  level: " + judgment["level"])
        print("  confidence: " + str(judgment.get("confidence", 0)))
        print("  summary: " + judgment["summary"])
        print("  action: " + judgment.get("recommended_action", ""))


if __name__ == "__main__":
    main()

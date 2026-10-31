# services/agent/tools.py
# The lookup tools of the triage agent.
# A tool does one small job and answers with one short text line.
# Tools never raise: a failed lookup returns a line saying it failed,
# so the brain can still finish its verdict with what it has.
# Every tool here only reads. Nothing in this file writes anything.

import ipaddress
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from sqlalchemy import text

from services.agent.database import engine

# Load the .env file from the project root (two folders up from here)
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def ip_history(source_ip):
    # What our own events table knows about this IP, as one text line.
    # FILTER counts only the rows that match the condition beside it.
    sql = """
        SELECT COUNT(*) AS total,
               COUNT(*) FILTER (WHERE outcome = 'failure') AS failures,
               COUNT(*) FILTER (WHERE outcome = 'success') AS successes,
               COUNT(DISTINCT username) AS usernames,
               MIN(event_time) AS first_seen,
               MAX(event_time) AS last_seen
        FROM events
        WHERE source_ip = :source_ip
    """
    with engine.connect() as connection:
        row = connection.execute(
            text(sql), {"source_ip": source_ip}
        ).mappings().one()
    if row["total"] == 0:
        return f"ip_history: no events in our logs for {source_ip}"
    return (
        f"ip_history: {source_ip} has {row['total']} events in our "
        f"logs, {row['failures']} failures, {row['successes']} "
        f"successes, {row['usernames']} distinct username(s), "
        f"first seen {row['first_seen']}, last seen {row['last_seen']}"
    )


def abuseipdb_check(source_ip):
    # Public reputation of the IP from AbuseIPDB, as one text line.
    # AbuseIPDB only knows public internet IPs, so private and
    # reserved addresses are answered locally, without any call.
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return f"abuseipdb: skipped, {source_ip} is not a valid IP"
    if address.is_private:
        return (
            f"abuseipdb: skipped, {source_ip} is a private or "
            "reserved address, it has no public reputation"
        )
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return "abuseipdb: not configured, no API key in .env"
    try:
        response = httpx.get(
            ABUSEIPDB_URL,
            params={"ipAddress": source_ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()["data"]
    except httpx.HTTPError:
        return f"abuseipdb: lookup failed for {source_ip}"
    country = data.get("countryCode") or "unknown"
    isp = data.get("isp") or "unknown"
    return (
        f"abuseipdb: {source_ip} abuse confidence "
        f"{data['abuseConfidenceScore']} percent, "
        f"{data['totalReports']} reports, country {country}, ISP {isp}"
    )


def gather_intel(source_ip):
    # Run every tool for one IP and return the list of text lines.
    # This list is exactly what build_triage_prompt expects as intel.
    if not source_ip:
        return ["intel: this alert has no source_ip, no lookups run"]
    return [ip_history(source_ip), abuseipdb_check(source_ip)]
def alert_facts(alert, events):
    # Hard facts about one alert, counted by code, not by the model.
    # The brain reads these lines instead of counting raw log lines
    # itself, because a small model counts and compares badly.
    failures = [e for e in events if e["outcome"] == "failure"]
    successes = [e for e in events if e["outcome"] == "success"]
    usernames = sorted({e["username"] for e in events if e["username"]})
    names = ", ".join(usernames) if usernames else "none"
    success_after = "no"
    if failures and successes:
        first_failure = min(e["event_time"] for e in failures)
        if any(e["event_time"] > first_failure for e in successes):
            success_after = "yes"
    try:
        is_private = ipaddress.ip_address(alert["source_ip"]).is_private
    except ValueError:
        is_private = False
    if is_private:
        source_kind = "private or reserved address, no public reputation exists"
    else:
        source_kind = "public internet address"
    return [
        f"facts: {len(events)} events in the window, "
        f"{len(failures)} failures, {len(successes)} successes",
        f"facts: login success after a failure: {success_after}",
        f"facts: distinct usernames tried: {len(usernames)} ({names})",
        f"facts: source {alert['source_ip']} is a {source_kind}",
    ]

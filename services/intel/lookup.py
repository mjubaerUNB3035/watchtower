# services/intel/lookup.py

import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

API_URL = "https://api.abuseipdb.com/api/v2/check"


# Check ip
def check_ip(ip):
    key = os.environ.get("ABUSEIPDB_API_KEY") or ""
    if not key:
        return None
    try:
        response = httpx.get(
            API_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        response.raise_for_status()
    except httpx.HTTPError:
        return None
    data = response.json()["data"]
    return {
        "ip": data["ipAddress"],
        "score": data["abuseConfidenceScore"],
        "reports": data["totalReports"],
        "country": data["countryCode"],
        "isp": data["isp"],
    }
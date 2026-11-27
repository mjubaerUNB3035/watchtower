# services/intel/service.py

from datetime import datetime, timedelta, timezone

from services.intel.database import get_intel, save_intel
from services.intel.lookup import check_ip

FRESH_DAYS = 7

# If Intel < 7 day - return cahce
# Else AbuseIPDB (cache)
# Get or check
def get_or_check(ip):
    cached = get_intel(ip)
    if cached is not None:
        age = datetime.now(timezone.utc) - cached["checked_at"]
        if age < timedelta(days=FRESH_DAYS):
            cached.pop("checked_at")
            return cached
    record = check_ip(ip)
    if record is None:
        return None
    save_intel(record)
    return record
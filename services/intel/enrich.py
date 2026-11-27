# services/intel/enrich.py

from sqlalchemy import text

from services.intel.database import engine
from services.intel.service import get_or_check


# Event ips
def event_ips():
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT DISTINCT source_ip FROM events WHERE source_ip IS NOT NULL ORDER BY source_ip")
        )
        return [row[0] for row in rows]


# Enrich all
def enrich_all():
    done = 0
    for ip in event_ips():
        record = get_or_check(ip)
        if record is None:
            print(ip, "no record")
            continue
        print(ip, "score:", record["score"], "reports:", record["reports"], record["country"], record["isp"])
        done += 1
    print("enriched:", done)


if __name__ == "__main__":
    enrich_all()
# WatchTower web access collector.
# Reads a web access log file, translates each line with
# parse_web_access_line, and sends the events to the ingest API.

import sys
from pathlib import Path

import httpx

from services.ingest.normalize import parse_web_access_line

# Host Name (in Event)
HOST = "watchtower-web"

# Ingest API listens.
API_URL = "http://127.0.0.1:8000/events"

# Read one log file and return the list of events found in it
# Lines that are not web events come back as None and are skipped
def collect_file(path: Path):
    events = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines:
        event = parse_web_access_line(line, HOST)
        if event is not None:
            events.append(event)
    return events


# Send one event to the ingest API.
# Returns the id the database gave the stored event.
def send_event(event) -> int:
    response = httpx.post(API_URL, json=event.model_dump(mode="json"))
    response.raise_for_status()
    return response.json()["id"]


def main():
    # The collector needs exactly one argument: the log file path.
    if len(sys.argv) != 2:
        print("Usage: python -m collectors.web_access <access-log-file>")
        raise SystemExit(1)

    path = Path(sys.argv[1])
    events = collect_file(path)

    # Send each event and print the stored id as the receipt.
    for event in events:
        new_id = send_event(event)
        print(f"stored {new_id} {event.event_type} {event.username} {event.outcome}")

    print(f"Sent {len(events)} events")


if __name__ == "__main__":
    main()

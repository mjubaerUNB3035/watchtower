# WatchTower Linux auth collector
# Reads a Linux auth.log file and translates each line
# with the ingest normalizer. Collectors stay dumb:
# this file knows how to read lines, nothing about
# databases or rules. Version 2 sends the events to
# the ingest API and prints the stored ids.
#
# Reference: what we take from one auth.log line.
#
# Line: 2026-10-18T12:02:11.441-03:00 watchtower-linux sshd[1821]: Failed password for md from 192.168.56.1 port 51234 ssh2
#
#   event_time  -> 2026-10-18T12:02:11.441-03:00
#   host        -> watchtower-linux
#   source      -> linux_auth
#   event_type  -> login_failed
#   username    -> md
#   source_ip   -> 192.168.56.1
#   outcome     -> failure
#   raw         -> the whole line, untouched

import sys
from pathlib import Path

import httpx

from services.ingest.normalize import parse_linux_auth_line

# The machine these logs come from. Every event this
# collector produces belongs to this host.
HOST = "watchtower-linux"

# Where the ingest API receives events.
API_URL = "http://127.0.0.1:8000/events"


def collect_file(path: Path) -> list:
    # Read one log file and return the events found in
    # it. Lines the normalizer does not know come back
    # as None and are skipped: a real auth.log is
    # mostly lines we do not collect.
    events = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines:
        event = parse_linux_auth_line(line, HOST)
        if event is not None:
            events.append(event)
    return events


def send_event(event) -> int:
    # Send one event to the ingest API and return the
    # id the database assigned to it.
    # model_dump(mode="json") turns the event object
    # into plain JSON-ready data: the datetime becomes
    # text, ready to travel in the request body.
    response = httpx.post(API_URL, json=event.model_dump(mode="json"))
    # If the API answered with an error code, stop
    # loudly here instead of pretending it worked.
    response.raise_for_status()
    return response.json()["id"]


def main() -> None:
    # The file to read is given on the command line:
    # python -m collectors.linux_auth <path-to-log-file>
    # sys.argv is the list of words the program was
    # started with: program name first, then arguments.
    if len(sys.argv) != 2:
        print("Usage: python -m collectors.linux_auth <path-to-log-file>")
        raise SystemExit(1)

    events = collect_file(Path(sys.argv[1]))

    for event in events:
        new_id = send_event(event)
        print("stored", new_id, event.event_type, event.username, event.outcome)

    print(f"Sent {len(events)} events")


if __name__ == "__main__":
    main()

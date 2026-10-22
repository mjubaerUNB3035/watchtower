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

import re
from datetime import datetime, timezone

from services.ingest.schema import SchemaEventIn

# Patterns for the two SSH password lines in auth.log.
# (?:invalid user )? matches the words "invalid user"
# when they appear, without becoming a result group.
# (\S+) captures the username, (\d+\.\d+\.\d+\.\d+)
# captures the IPv4 address.
FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(\S+) "
    r"from (\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?:invalid user )?(\S+) "
    r"from (\d+\.\d+\.\d+\.\d+)"
)


def _event_time_from_line(line: str) -> datetime:
    # auth.log lines begin with the time, in ISO format
    # on this system, example: 2026-10-18T03:30:00+00:00
    # Take the first word of the line and parse it.
    # If a line ever has no time zone, assume UTC:
    # that is the project rule for all event times.
    first_word = line.split(maxsplit=1)[0]
    moment = datetime.fromisoformat(first_word)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def parse_linux_auth_line(line: str, host: str) -> SchemaEventIn | None:
    # Translate one Linux auth.log line into an event.
    # Returns None when the line is not an SSH password
    # event, so the collector can simply skip it.
    line = line.strip()
    failed = FAILED_PASSWORD.search(line)
    if failed:
        return SchemaEventIn(
            event_time=_event_time_from_line(line),
            host=host,
            source="linux_auth",
            event_type="login_failed",
            username=failed.group(1),
            source_ip=failed.group(2),
            outcome="failure",
            raw=line,
        )
    accepted = ACCEPTED_PASSWORD.search(line)
    if accepted:
        return SchemaEventIn(
            event_time=_event_time_from_line(line),
            host=host,
            source="linux_auth",
            event_type="login_success",
            username=accepted.group(1),
            source_ip=accepted.group(2),
            outcome="success",
            raw=line,
        )
    return None

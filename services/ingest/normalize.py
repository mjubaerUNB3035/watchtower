# services/ingest/normalize.py
# log line parsers: linux auth and web access

import re
from datetime import datetime, timezone

from services.ingest.schema import SchemaEventIn

# ssh password lines: group 1 is username, group 2 is source ip
FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(\S+) "
    r"from (\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?:invalid user )?(\S+) "
    r"from (\d+\.\d+\.\d+\.\d+)"
)


def _event_time_from_line(line: str) -> datetime:
    # first word of the line as event time, UTC if no zone
    first_word = line.split(maxsplit=1)[0]
    moment = datetime.fromisoformat(first_word)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def parse_linux_auth_line(line: str, host: str) -> SchemaEventIn | None:
    # auth line to a login event, none if not a password line
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

# web access log pattern
WEB_ACCESS = re.compile(
    r'^(\d+\.\d+\.\d+\.\d+) \S+ (\S+) \[([^\]]+)\] "[A-Z]+ [^"]*" (\d{3})\b'
)


def parse_web_access_line(line: str, host: str) -> SchemaEventIn | None:
    # web access line to an http event, none if no match
    match = WEB_ACCESS.match(line.strip())

    if match is None:
        return None

    source_ip, username_text, time_text, status_text = match.groups()

    try:
        event_time = datetime.strptime(time_text, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    status = int(status_text)

    if status < 400:
        event_type = "http_request"
        outcome = "success"
    elif status < 500:
        event_type = "http_client_error"
        outcome = "failure"
    else:
        event_type = "http_server_error"
        outcome = "failure"

    username = None if username_text == "-" else username_text

    return SchemaEventIn(
        event_time=event_time,
        host=host,
        source="web_access",
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        outcome=outcome,
        raw=line.strip(),
    )

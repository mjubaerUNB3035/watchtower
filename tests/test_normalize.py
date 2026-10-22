# Tests for the Linux auth normalizer and collector.
# Run with: python -m pytest
# Each test states what one kind of log line must
# become, so a future change cannot silently break
# the translation.

from pathlib import Path

from collectors.linux_auth import collect_file
from services.ingest.normalize import parse_linux_auth_line

FAILED_LINE = (
    "2026-10-18T12:02:11.441-03:00 watchtower-linux sshd[1821]: "
    "Failed password for md from 192.168.56.1 port 51234 ssh2"
)
INVALID_USER_LINE = (
    "2026-10-18T12:03:02.105-03:00 watchtower-linux sshd[1830]: "
    "Failed password for invalid user admin from 192.168.56.1 "
    "port 51240 ssh2"
)
ACCEPTED_LINE = (
    "2026-10-18T12:04:45.902-03:00 watchtower-linux sshd[1844]: "
    "Accepted password for md from 192.168.56.1 port 51255 ssh2"
)
SUDO_LINE = (
    "2026-10-18T12:05:10.310-03:00 watchtower-linux sudo: "
    "md : TTY=pts/0 ; COMMAND=/usr/bin/tail"
)


def test_failed_password_line():
    event = parse_linux_auth_line(FAILED_LINE, "watchtower-linux")
    assert event is not None
    assert event.event_type == "login_failed"
    assert event.username == "md"
    assert event.source_ip == "192.168.56.1"
    assert event.outcome == "failure"
    assert event.source == "linux_auth"
    assert event.raw == FAILED_LINE


def test_invalid_user_line():
    event = parse_linux_auth_line(INVALID_USER_LINE, "watchtower-linux")
    assert event is not None
    assert event.event_type == "login_failed"
    assert event.username == "admin"


def test_accepted_password_line():
    event = parse_linux_auth_line(ACCEPTED_LINE, "watchtower-linux")
    assert event is not None
    assert event.event_type == "login_success"
    assert event.outcome == "success"


def test_other_lines_are_skipped():
    assert parse_linux_auth_line(SUDO_LINE, "watchtower-linux") is None


def test_collect_file_counts_only_events():
    events = collect_file(Path("tests/fixtures/auth_sample.log"))
    assert len(events) == 4

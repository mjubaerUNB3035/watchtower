# Tests for parse_web_access_line, the web log translator.

from services.ingest.normalize import parse_web_access_line
from pathlib import Path
from collectors.web_access import collect_file

HOST = "watchtower-web"

# The same lines as tests/fixtures/access_sample.log.
LINE_200 = '192.168.56.1 - - [22/Oct/2026:01:25:10 -0300] "GET / HTTP/1.1" 200 1043 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
LINE_404 = '203.0.113.45 - - [22/Oct/2026:01:26:02 -0300] "GET /admin HTTP/1.1" 404 512 "-" "Mozilla/5.0 (compatible; scanner)"'
LINE_401 = '203.0.113.45 - admin [22/Oct/2026:01:30:00 -0300] "POST /login HTTP/1.1" 401 231 "-" "curl/8.0"'
LINE_500 = '192.168.56.1 - - [22/Oct/2026:01:31:44 -0300] "GET /index.html HTTP/1.1" 500 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
LINE_JUNK = "this is not a web log line at all"


def test_web_200_is_http_request_success():
    event = parse_web_access_line(LINE_200, HOST)
    assert event is not None
    assert event.event_type == "http_request"
    assert event.outcome == "success"
    assert event.source == "web_access"
    assert event.username is None
    assert event.source_ip == "192.168.56.1"
    assert event.raw == LINE_200


def test_web_404_is_client_error_failure():
    event = parse_web_access_line(LINE_404, HOST)
    assert event is not None
    assert event.event_type == "http_client_error"
    assert event.outcome == "failure"
    assert event.source_ip == "203.0.113.45"


def test_web_401_keeps_username():
    event = parse_web_access_line(LINE_401, HOST)
    assert event is not None
    assert event.username == "admin"
    assert event.event_type == "http_client_error"
    assert event.outcome == "failure"


def test_web_500_is_server_error_failure():
    event = parse_web_access_line(LINE_500, HOST)
    assert event is not None
    assert event.event_type == "http_server_error"
    assert event.outcome == "failure"


def test_web_junk_line_returns_none():
    assert parse_web_access_line(LINE_JUNK, HOST) is None

# Test Web_access file
def test_collect_file_reads_fixture():
    # collect_file on the sample file gives exactly 4 events.
    # The junk line is skipped by the translator.
    events = collect_file(Path("tests/fixtures/access_sample.log"))
    assert len(events) == 4
    assert events[0].event_type == "http_request"
    assert events[2].username == "admin"

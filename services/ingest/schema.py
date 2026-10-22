from datetime import datetime
from pydantic import BaseModel

class SchemaEventIn(BaseModel):
    event_time: datetime  # when it happened, always UTC
    host: str  # machine it happened on, example: watchtower-linux
    source: str  # which log it came from, example: linux_auth
    event_type: str  # kind of event, example: login_failed
    username: str | None = None  # account involved, if the log has one
    source_ip: str | None = None  # IP involved, if the log has one
    outcome: str  # result of the event, example: failure or success
    raw: str  # the original log line, always kept, never edited
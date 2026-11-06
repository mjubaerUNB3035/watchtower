# services/ingest/main.py
# ingest api endpoints
# run: uvicorn services.ingest.main:app --port 8000

from fastapi import FastAPI
from services.ingest.schema import SchemaEventIn
from services.ingest.database import save_event, search_events


app = FastAPI(title="WatchTower Ingest API")


@app.get("/health")
def health_check():
    # api health check
    return {"status": "ok", "service": "ingest"}

@app.post("/events")
def receive_event(event: SchemaEventIn):
    # save one posted event, return its stored id
    new_id = save_event(event)
    return {
        "received": True,
        "stored": True,
        "id": new_id,
        "host": event.host,
        "event_type": event.event_type,
        "outcome": event.outcome,
    }

@app.get("/events")
def list_events(source: str | None = None,
                event_type: str | None = None,
                username: str | None = None,
                source_ip: str | None = None,
                limit: int = 100):
    # search events with optional filters
    return search_events(source=source, event_type=event_type,
                         username=username, source_ip=source_ip,
                         limit=limit)

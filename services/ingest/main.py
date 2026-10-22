# WatchTower Ingest API
# This service is the front door of WatchTower.
# Collectors send security log events here as JSON.
# This file starts small: it creates the FastAPI app and
# adds one health route so we can prove the service runs.
# Event receiving and database storage come in the next steps.

from fastapi import FastAPI
from services.ingest.schema import SchemaEventIn
from services.ingest.database import save_event


# The app object is the whole web service.
# uvicorn runs this object when we start the server.
app = FastAPI(title="WatchTower Ingest API")


@app.get("/health")
def health_check():
    # Health route: a caller asks "are you alive?"
    # and the service answers with a small JSON reply.
    # Other parts of the system use this before sending real work.
    return {"status": "ok", "service": "ingest"}

@app.post("/events")
def receive_event(event: SchemaEventIn):
    # Receive route: a collector sends one event here.
    # FastAPI checks the event against the EventIn schema
    # before this function runs. A bad event never gets here:
    # FastAPI answers with a 422 error by itself.
    # Saving to PostgreSQL is the next step, so for now the
    # service confirms what it received.
    new_id = save_event(event)
    return {
        "received": True,
        "stored": True,
        "id": new_id,
        "host": event.host,
        "event_type": event.event_type,
        "outcome": event.outcome,
    }

# services/api/main.py
# The dashboard API: HTTP endpoints over the read queries.
# The browser speaks JSON to this app; this app speaks SQL
# through database.py. The one write (human review) is passed
# to the agent's review_verdict, so its rules stay in one place.
# Run: uvicorn services.api.main:app --port 8001

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from services.agent.brain import VERDICTS
from services.agent.database import review_verdict
from services.api.database import (
    create_incident,
    get_alert_detail,
    get_incident,
    get_incident_for_alert,
    incident_eligible,
    list_alerts,
    list_incidents,
    overview_counts,
    shift_summary,
    update_incident,
    list_hosts,
    list_users,

)

app = FastAPI(title="WatchTower Dashboard API")

# The dashboard page runs on port 5173. A browser blocks a page
# from calling a different port unless the API allows it (CORS).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReviewIn(BaseModel):
    # The JSON body of one review click.
    decision: str
    human_verdict: str | None = None


class IncidentCreateIn(BaseModel):
    alert_id: int


class IncidentUpdateIn(BaseModel):
    status: str
    notes: str | None = None


@app.get("/health")
def health():
    return {"status": "ok", "service": "dashboard-api"}


@app.get("/overview")
def overview():
    return overview_counts()


@app.get("/alerts")
def alerts():
    return list_alerts()


@app.get("/alerts/{alert_id}")
def alert_detail(alert_id: int):
    detail = get_alert_detail(alert_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="alert not found")
    detail["incident"] = get_incident_for_alert(alert_id)
    return detail


@app.post("/verdicts/{verdict_id}/review")
def review(verdict_id: int, body: ReviewIn):
    if body.decision not in ("approved", "corrected"):
        raise HTTPException(
            status_code=400, detail="decision must be approved or corrected"
        )
    if body.decision == "corrected" and body.human_verdict not in VERDICTS:
        raise HTTPException(
            status_code=400,
            detail="human_verdict must be one of the 3 verdict words",
        )
    saved = review_verdict(verdict_id, body.decision, body.human_verdict)
    if saved is None:
        raise HTTPException(status_code=409, detail="verdict is not pending")
    return {"reviewed": verdict_id, "decision": body.decision}


INCIDENT_STATUSES = ("open", "investigating", "closed")


@app.get("/incidents")
def incidents_list():
    return list_incidents()


@app.post("/incidents")
def incidents_create(body: IncidentCreateIn):
    detail = get_alert_detail(body.alert_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="alert not found")
    if get_incident_for_alert(body.alert_id) is not None:
        raise HTTPException(status_code=409, detail="incident already exists")
    if not incident_eligible(detail):
        raise HTTPException(
            status_code=400, detail="alert is not a reviewed true positive"
        )
    return create_incident(detail)


@app.get("/incidents/{incident_id}")
def incidents_detail(incident_id: int):
    incident = get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    detail = get_alert_detail(incident["alert_id"])
    events = detail.pop("events", [])
    return {"incident": incident, "alert": detail, "events": events}


@app.patch("/incidents/{incident_id}")
def incidents_update(incident_id: int, body: IncidentUpdateIn):
    if body.status not in INCIDENT_STATUSES:
        raise HTTPException(status_code=400, detail="invalid status")
    incident = get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    notes = body.notes if body.notes is not None else incident["notes"]
    update_incident(incident_id, body.status, notes)
    return get_incident(incident_id)

@app.get("/shift-log")
def shift_log(hours: int = 24):
    if hours < 1 or hours > 168:
        raise HTTPException(status_code=400, detail="hours must be 1 to 168")
    return shift_summary(hours)

@app.get("/hosts")
def hosts():
    return {"hosts": list_hosts(), "users": list_users()}

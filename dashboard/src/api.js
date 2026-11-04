// src/api.js
// Dashboard API client (port 8001).

const API = "http://127.0.0.1:8001";

async function getJson(path) {
    const res = await fetch(API + path);
    if (!res.ok) {
        throw new Error(`API ${res.status} on ${path}`);
    }
    return res.json();
}

export function getOverview() {
    return getJson("/overview");
}

export function getAlerts() {
    return getJson("/alerts");
}

export function getAlert(id) {
    return getJson(`/alerts/${id}`);
}

export async function reviewVerdict(verdictId, decision, humanVerdict) {
    const res = await fetch(`${API}/verdicts/${verdictId}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            decision: decision,
            human_verdict: humanVerdict ?? null,
        }),
    });
    if (!res.ok) {
        throw new Error(`review failed: API ${res.status}`);
    }
    return res.json();
}
export function getIncidents() {
    return getJson("/incidents");
}

export function getIncident(id) {
    return getJson(`/incidents/${id}`);
}

export async function createIncident(alertId) {
    const res = await fetch(`${API}/incidents`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: alertId }),
    });
    if (!res.ok) {
        throw new Error(`create incident failed: API ${res.status}`);
    }
    return res.json();
}

export async function updateIncident(id, status, notes) {
    const res = await fetch(`${API}/incidents/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: status, notes: notes ?? null }),
    });
    if (!res.ok) {
        throw new Error(`update incident failed: API ${res.status}`);
    }
    return res.json();
}

// shift summary for a window in hours
export function getShiftLog(hours) {
    return getJson(`/shift-log?hours=${hours}`);
}

// hosts and users summary
export function getHosts() {
    return getJson("/hosts");
}

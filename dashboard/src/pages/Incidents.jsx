import { useEffect, useState } from "react";
import { getIncident, getIncidents, updateIncident } from "../api";

const STATUSES = ["open", "investigating", "closed"];

const STATUS_STYLE = {
    open: "text-amber-400",
    investigating: "text-sky-400",
    closed: "text-emerald-400",
};

function IncidentDetail({ incidentId, onBack }) {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [notes, setNotes] = useState("");
    const [busy, setBusy] = useState(false);
    const [notice, setNotice] = useState(null);

    function load() {
        getIncident(incidentId)
            .then((d) => {
                setData(d);
                setNotes(d.incident.notes || "");
            })
            .catch((e) => setError(e.message));
    }

    useEffect(() => {
        setData(null);
        setNotice(null);
        load();
    }, [incidentId]);

    if (error) {
        return <p className="text-red-400">Could not load incident: {error}</p>;
    }
    if (!data) {
        return <p className="text-slate-400">Loading...</p>;
    }

    const inc = data.incident;
    const a = data.alert;
    const events = data.events || [];

    async function save(status) {
        setBusy(true);
        try {
            const saved = await updateIncident(inc.id, status, notes);
            setData({ ...data, incident: saved });
            setNotice(`Saved: status ${saved.status}.`);
        } catch (e) {
            setNotice(`Save failed: ${e.message}`);
        }
        setBusy(false);
    }

    return (
        <div>
            <button onClick={onBack} className="text-sm text-sky-400 hover:underline">
                Back to incidents
            </button>
            <h2 className="mt-2 text-2xl font-bold">
                Incident {inc.id}: {inc.title}
            </h2>
            <p className="mt-1 text-sm text-slate-400">
                From alert {a.id} ({a.rule_name}, severity {a.severity}), source{" "}
                {a.source_ip}, user {a.username || "-"}
            </p>
            <p className="mt-1 text-sm text-slate-400">
                Final verdict: {a.human_verdict || a.verdict} (review {a.review_status})
            </p>

            <div className="mt-4 rounded border border-slate-800 bg-slate-900 p-4">
                <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm text-slate-400">Status:</span>
                    {STATUSES.map((s) => (
                        <button
                            key={s}
                            onClick={() => save(s)}
                            disabled={busy}
                            className={`rounded px-3 py-1 text-sm ${inc.status === s
                                    ? "bg-slate-700 font-semibold"
                                    : "bg-slate-800 hover:bg-slate-700"
                                }`}
                        >
                            {s}
                        </button>
                    ))}
                    <span className={`text-sm font-semibold ${STATUS_STYLE[inc.status]}`}>
                        {inc.status}
                    </span>
                </div>
                <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    rows={3}
                    placeholder="Working notes on this case"
                    className="mt-3 w-full rounded border border-slate-800 bg-slate-950 p-2 text-sm"
                />
                <button
                    onClick={() => save(inc.status)}
                    disabled={busy}
                    className="mt-2 rounded bg-sky-800 px-4 py-2 text-sm font-semibold hover:bg-sky-700 disabled:opacity-50"
                >
                    Save notes
                </button>
                {notice && <p className="mt-3 text-sm text-amber-300">{notice}</p>}
                {inc.closed_at && (
                    <p className="mt-2 text-sm text-slate-400">Closed at {inc.closed_at}</p>
                )}
            </div>

            <h3 className="mt-6 mb-2 font-semibold">Timeline ({events.length} events)</h3>
            <table className="w-full text-left text-sm">
                <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 pr-4">Time (UTC)</th>
                        <th className="py-2 pr-4">Type</th>
                        <th className="py-2 pr-4">User</th>
                        <th className="py-2 pr-4">Outcome</th>
                        <th className="py-2">Raw line</th>
                    </tr>
                </thead>
                <tbody>
                    {events.map((e) => (
                        <tr key={e.id} className="border-b border-slate-900 align-top">
                            <td className="py-2 pr-4 whitespace-nowrap">{e.event_time}</td>
                            <td className="py-2 pr-4">{e.event_type}</td>
                            <td className="py-2 pr-4">{e.username || "-"}</td>
                            <td className="py-2 pr-4">{e.outcome}</td>
                            <td className="py-2 font-mono text-xs text-slate-400">{e.raw}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

export default function Incidents() {
    const [incidents, setIncidents] = useState(null);
    const [error, setError] = useState(null);
    const [selected, setSelected] = useState(null);
    const [reloadKey, setReloadKey] = useState(0);

    useEffect(() => {
        getIncidents().then(setIncidents).catch((e) => setError(e.message));
    }, [reloadKey]);

    if (selected !== null) {
        return (
            <IncidentDetail
                incidentId={selected}
                onBack={() => {
                    setSelected(null);
                    setReloadKey((k) => k + 1);
                }}
            />
        );
    }
    if (error) {
        return <p className="text-red-400">Could not load incidents: {error}</p>;
    }
    if (!incidents) {
        return <p className="text-slate-400">Loading...</p>;
    }

    return (
        <div>
            <h2 className="mb-4 text-2xl font-bold">Incidents</h2>
            {incidents.length === 0 ? (
                <p className="text-slate-400">No incidents yet.</p>
            ) : (
                <table className="w-full text-left text-sm">
                    <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                            <th className="py-2 pr-4">ID</th>
                            <th className="py-2 pr-4">Title</th>
                            <th className="py-2 pr-4">Severity</th>
                            <th className="py-2 pr-4">Source IP</th>
                            <th className="py-2 pr-4">Status</th>
                            <th className="py-2">Created</th>
                        </tr>
                    </thead>
                    <tbody>
                        {incidents.map((i) => (
                            <tr
                                key={i.id}
                                onClick={() => setSelected(i.id)}
                                className="cursor-pointer border-b border-slate-900 hover:bg-slate-900"
                            >
                                <td className="py-2 pr-4">{i.id}</td>
                                <td className="py-2 pr-4">{i.title}</td>
                                <td className="py-2 pr-4">{i.severity}</td>
                                <td className="py-2 pr-4">{i.source_ip}</td>
                                <td className={`py-2 font-semibold ${STATUS_STYLE[i.status]}`}>
                                    {i.status}
                                </td>
                                <td className="py-2">{i.created_at}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
}

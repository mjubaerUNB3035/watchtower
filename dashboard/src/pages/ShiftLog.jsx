import { useEffect, useState } from "react";
import { getShiftLog } from "../api";

// time windows for the summary
const WINDOWS = [
    { hours: 8, label: "Last 8 hours" },
    { hours: 12, label: "Last 12 hours" },
    { hours: 24, label: "Last 24 hours" },
    { hours: 168, label: "Last 7 days" },
];

// one summary card
function Stat({ label, value }) {
    return (
        <div className="rounded border border-slate-800 bg-slate-900 p-4">
            <div className="text-sm text-slate-400">{label}</div>
            <div className="mt-1 text-3xl font-bold">{value}</div>
        </div>
    );
}

export default function ShiftLog() {
    // picked window, fetched summary, load error
    const [hours, setHours] = useState(24);
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);

    // refetch when the window changes
    useEffect(() => {
        setData(null);
        getShiftLog(hours).then(setData).catch((e) => setError(e.message));
    }, [hours]);

    return (
        <div>
            <h2 className="mb-4 text-2xl font-bold">Shift log</h2>
            <div className="mb-4 flex flex-wrap gap-2">
                {WINDOWS.map((w) => (
                    <button
                        key={w.hours}
                        onClick={() => setHours(w.hours)}
                        className={`rounded px-3 py-1 text-sm ${hours === w.hours
                                ? "bg-sky-700 font-semibold"
                                : "bg-slate-800 hover:bg-slate-700"
                            }`}
                    >
                        {w.label}
                    </button>
                ))}
            </div>

            {error && <p className="text-red-400">Could not load shift log: {error}</p>}
            {!error && !data && <p className="text-slate-400">Loading...</p>}

            {data && (
                <div>
                    {/* summary cards */}
                    <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
                        <Stat label="Events in window" value={data.events_in_window} />
                        <Stat label="New alerts" value={data.new_alerts.length} />
                        <Stat label="Reviews done" value={data.reviews_done.length} />
                        <Stat label="Incidents opened" value={data.incidents_opened.length} />
                        <Stat label="Open incidents now" value={data.open_incidents} />
                        <Stat label="Pending reviews" value={data.pending_reviews} />
                    </div>

                    <h3 className="mt-6 mb-2 font-semibold">New alerts</h3>
                    {data.new_alerts.length === 0 ? (
                        <p className="text-sm text-slate-400">None in this window.</p>
                    ) : (
                        <ul className="space-y-1 text-sm">
                            {data.new_alerts.map((a) => (
                                <li key={a.id}>
                                    Alert {a.id}: {a.rule_name} from {a.source_ip} ({a.event_count}{" "}
                                    events), final verdict {a.human_verdict || a.verdict || "not triaged"},
                                    review {a.review_status || "awaiting triage"}
                                </li>
                            ))}
                        </ul>
                    )}

                    <h3 className="mt-6 mb-2 font-semibold">Reviews done</h3>
                    {data.reviews_done.length === 0 ? (
                        <p className="text-sm text-slate-400">None in this window.</p>
                    ) : (
                        <ul className="space-y-1 text-sm">
                            {data.reviews_done.map((v) => (
                                <li key={v.id}>
                                    Alert {v.alert_id}: model said {v.verdict}, final{" "}
                                    {v.human_verdict || v.verdict} ({v.status})
                                </li>
                            ))}
                        </ul>
                    )}

                    <h3 className="mt-6 mb-2 font-semibold">Incidents opened</h3>
                    {data.incidents_opened.length === 0 ? (
                        <p className="text-sm text-slate-400">None in this window.</p>
                    ) : (
                        <ul className="space-y-1 text-sm">
                            {data.incidents_opened.map((i) => (
                                <li key={i.id}>
                                    Incident {i.id}: {i.title} ({i.status})
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            )}
        </div>
    );
}

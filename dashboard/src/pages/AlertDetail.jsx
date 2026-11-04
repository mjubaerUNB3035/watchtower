import { useEffect, useState } from "react";
import { createIncident, getAlert, reviewVerdict } from "../api";

const VERDICTS = ["true_positive", "false_positive", "needs_more_info"];

function Fact({ label, value }) {
    return (
        <div>
            <div className="text-xs text-slate-500">{label}</div>
            <div className="text-sm">{value}</div>
        </div>
    );
}

export default function AlertDetail({ alertId, onBack }) {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [correction, setCorrection] = useState(null);
    const [busy, setBusy] = useState(false);
    const [notice, setNotice] = useState(null);

    function load() {
        getAlert(alertId).then(setData).catch((e) => setError(e.message));
    }

    useEffect(() => {
        setData(null);
        setError(null);
        setNotice(null);
        setCorrection(null);
        load();
    }, [alertId]);

    if (error) {
        return <p className="text-red-400">Could not load alert: {error}</p>;
    }
    if (!data) {
        return <p className="text-slate-400">Loading...</p>;
    }

    const a = data;
    const events = data.events || [];
    const pending = a.review_status === "pending";
    const finalVerdict = a.human_verdict || a.verdict;
    const eligible =
        (a.review_status === "approved" || a.review_status === "corrected") &&
        finalVerdict === "true_positive";

    async function approve() {
        setBusy(true);
        try {
            await reviewVerdict(a.verdict_id, "approved");
            setNotice("Verdict approved.");
            load();
        } catch (e) {
            setNotice(`Review failed: ${e.message}`);
        }
        setBusy(false);
    }

    async function confirmCorrection() {
        if (!correction) {
            return;
        }
        setBusy(true);
        try {
            await reviewVerdict(a.verdict_id, "corrected", correction);
            setNotice(`Corrected to ${correction}.`);
            load();
        } catch (e) {
            setNotice(`Review failed: ${e.message}`);
        }
        setBusy(false);
    }

    async function fileIncident() {
        setBusy(true);
        try {
            const inc = await createIncident(a.id);
            setNotice(`Incident ${inc.id} created.`);
            load();
        } catch (e) {
            setNotice(`Create incident failed: ${e.message}`);
        }
        setBusy(false);
    }

    return (
        <div>
            <button onClick={onBack} className="text-sm text-sky-400 hover:underline">
                Back to queue
            </button>
            <h2 className="mt-2 text-2xl font-bold">
                Alert {a.id}: {a.rule_name}
            </h2>

            <div className="mt-4 grid grid-cols-2 gap-4 rounded border border-slate-800 bg-slate-900 p-4 lg:grid-cols-4">
                <Fact label="Severity" value={a.severity} />
                <Fact label="MITRE" value={a.mitre_technique} />
                <Fact label="Host" value={a.host} />
                <Fact label="Source IP" value={a.source_ip} />
                <Fact label="User" value={a.username || "-"} />
                <Fact label="Events" value={a.event_count} />
                <Fact label="Window start" value={a.window_start} />
                <Fact label="Window end" value={a.window_end} />
            </div>

            <div className="mt-4 rounded border border-slate-800 bg-slate-900 p-4">
                <h3 className="font-semibold">Agent verdict</h3>
                {a.verdict ? (
                    <div className="mt-2 space-y-1 text-sm">
                        <p>
                            Verdict: <span className="font-semibold">{a.verdict}</span>
                            {" "}(confidence {a.confidence}, model {a.model})
                        </p>
                        <p className="text-slate-300">{a.summary}</p>
                        {a.recommended_action && (
                            <p>Recommended action: {a.recommended_action}</p>
                        )}
                        <p>
                            Review: <span className="font-semibold">{a.review_status}</span>
                            {a.human_verdict && `, corrected to ${a.human_verdict}`}
                        </p>
                    </div>
                ) : (
                    <p className="mt-2 text-sm text-slate-400">Not triaged yet.</p>
                )}

                {pending && (
                    <div className="mt-4 border-t border-slate-800 pt-4">
                        <button
                            onClick={approve}
                            disabled={busy}
                            className="rounded bg-emerald-700 px-4 py-2 text-sm font-semibold hover:bg-emerald-600 disabled:opacity-50"
                        >
                            Approve verdict
                        </button>
                        <div className="mt-3 flex flex-wrap items-center gap-2">
                            {VERDICTS.map((v) => (
                                <button
                                    key={v}
                                    onClick={() => setCorrection(v)}
                                    className={`rounded px-3 py-1 text-sm ${correction === v
                                        ? "bg-sky-700 font-semibold"
                                        : "bg-slate-800 hover:bg-slate-700"
                                        }`}
                                >
                                    {v}
                                </button>
                            ))}
                            <button
                                onClick={confirmCorrection}
                                disabled={busy || !correction}
                                className="rounded bg-sky-800 px-4 py-1 text-sm font-semibold hover:bg-sky-700 disabled:opacity-50"
                            >
                                Confirm correction
                            </button>
                        </div>
                    </div>
                )}
                {notice && <p className="mt-3 text-sm text-amber-300">{notice}</p>}
            </div>

            <div className="mt-4 rounded border border-slate-800 bg-slate-900 p-4">
                <h3 className="font-semibold">Incident</h3>
                {a.incident ? (
                    <p className="mt-2 text-sm">
                        Filed as incident {a.incident.id}, status{" "}
                        <span className="font-semibold">{a.incident.status}</span>.
                    </p>
                ) : eligible ? (
                    <button
                        onClick={fileIncident}
                        disabled={busy}
                        className="mt-2 rounded bg-amber-700 px-4 py-2 text-sm font-semibold hover:bg-amber-600 disabled:opacity-50"
                    >
                        Create incident
                    </button>
                ) : (
                    <p className="mt-2 text-sm text-slate-400">
                        Only a reviewed true positive can become an incident.
                    </p>
                )}
            </div>

            <h3 className="mt-6 mb-2 font-semibold">Evidence events ({events.length})</h3>
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

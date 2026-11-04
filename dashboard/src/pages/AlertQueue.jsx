import { useEffect, useState } from "react";
import { getAlerts } from "../api";

const REVIEW_STYLE = {
    pending: "text-amber-400",
    approved: "text-emerald-400",
    corrected: "text-sky-400",
};

export default function AlertQueue({ onSelect }) {
    const [alerts, setAlerts] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        getAlerts().then(setAlerts).catch((e) => setError(e.message));
    }, []);

    if (error) {
        return <p className="text-red-400">Could not load alerts: {error}</p>;
    }
    if (!alerts) {
        return <p className="text-slate-400">Loading...</p>;
    }

    return (
        <div>
            <h2 className="mb-4 text-2xl font-bold">Alert queue</h2>
            <table className="w-full text-left text-sm">
                <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 pr-4">ID</th>
                        <th className="py-2 pr-4">Rule</th>
                        <th className="py-2 pr-4">Severity</th>
                        <th className="py-2 pr-4">Source IP</th>
                        <th className="py-2 pr-4">User</th>
                        <th className="py-2 pr-4">Count</th>
                        <th className="py-2 pr-4">Verdict</th>
                        <th className="py-2">Review</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts.map((a) => (
                        <tr
                            key={a.id}
                            onClick={() => onSelect(a.id)}
                            className="cursor-pointer border-b border-slate-900 hover:bg-slate-900"
                        >
                            <td className="py-2 pr-4">{a.id}</td>
                            <td className="py-2 pr-4">{a.rule_name}</td>
                            <td className="py-2 pr-4">{a.severity}</td>
                            <td className="py-2 pr-4">{a.source_ip}</td>
                            <td className="py-2 pr-4">{a.username || "-"}</td>
                            <td className="py-2 pr-4">{a.event_count}</td>
                            <td className="py-2 pr-4">{a.verdict || "not triaged"}</td>
                            <td className={`py-2 font-semibold ${REVIEW_STYLE[a.review_status] || "text-slate-500"}`}>
                                {a.review_status || "awaiting triage"}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

import { useEffect, useState } from "react";
import { getOverview } from "../api";

function Card({ label, value }) {
    return (
        <div className="rounded border border-slate-800 bg-slate-900 p-4">
            <div className="text-sm text-slate-400">{label}</div>
            <div className="mt-1 text-3xl font-bold">{value}</div>
        </div>
    );
}

export default function Overview() {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        getOverview().then(setData).catch((e) => setError(e.message));
    }, []);

    if (error) {
        return <p className="text-red-400">Could not load overview: {error}</p>;
    }
    if (!data) {
        return <p className="text-slate-400">Loading...</p>;
    }

    const finals = data.final_verdicts || {};

    return (
        <div>
            <h2 className="mb-4 text-2xl font-bold">Overview</h2>
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
                <Card label="Events stored" value={data.events} />
                <Card label="Alerts" value={data.alerts} />
                <Card label="Pending reviews" value={data.pending_reviews} />
                <Card label="True positives (final)" value={finals.true_positive || 0} />
                <Card label="False positives (final)" value={finals.false_positive || 0} />
                <Card label="Human corrections" value={data.corrections} />
            </div>
        </div>
    );
}

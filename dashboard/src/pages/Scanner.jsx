import { useEffect, useState } from "react";
import { getScans } from "../api";



// scanner page: latest scan result for each machine
export default function Scanner() {
    const [scans, setScans] = useState(null);
    const [error, setError] = useState(null);

    // load the scan results when the page opens
    useEffect(() => {
        getScans()
            .then(setScans)
            .catch((err) => setError(err.message));
    }, []);

    if (error) {
        return <p className="text-red-400">Failed to load scans: {error}</p>;
    }
    if (scans === null) {
        return <p className="text-slate-400">Loading scans...</p>;
    }

    return (
        <div className="space-y-6">
            <h1 className="text-2xl font-bold">Scanner</h1>
            {scans.map((scan) => (
                <div key={scan.host} className="rounded-lg border border-slate-700 p-4">
                    <h2 className="text-lg font-semibold">{scan.host}</h2>
                    <p className="text-sm text-slate-400">
                        Scanned at {new Date(scan.scanned_at).toLocaleString()}
                    </p>
                    {scan.open_ports.length === 0 ? (
                        <p className="mt-2 text-slate-400">No open ports found.</p>
                    ) : (
                        <table className="mt-2 w-full text-left">
                            <thead>
                                <tr>
                                    <th className="py-1">Port</th>
                                    <th className="py-1">Service</th>
                                </tr>
                            </thead>
                            <tbody>
                                {scan.open_ports.map((port) => (
                                    <tr key={port.port} className="border-t border-slate-700">
                                        <td className="py-1">{port.port}</td>
                                        <td className="py-1">{port.service}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            ))}
        </div>
    );
}

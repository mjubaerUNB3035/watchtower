import { useEffect, useState } from "react";
import { getHosts } from "../api";

// short timestamp for the tables
function fmt(t) {
    return t.replace("T", " ").slice(0, 19);
}

export default function Hosts() {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        getHosts().then(setData).catch((e) => setError(e.message));
    }, []);

    if (error) {
        return <p className="text-red-400">Could not load hosts: {error}</p>;
    }
    if (!data) {
        return <p className="text-slate-400">Loading...</p>;
    }

    return (
        <div>
            <h2 className="mb-4 text-2xl font-bold">Hosts</h2>
            <table className="w-full text-sm">
                <thead>
                    <tr className="text-left text-slate-400">
                        <th className="py-2 pr-4">Host</th>
                        <th className="py-2 pr-4">Events</th>
                        <th className="py-2 pr-4">Failures</th>
                        <th className="py-2 pr-4">Successes</th>
                        <th className="py-2 pr-4">Users</th>
                        <th className="py-2 pr-4">Source IPs</th>
                        <th className="py-2 pr-4">First seen</th>
                        <th className="py-2 pr-4">Last seen</th>
                    </tr>
                </thead>
                <tbody>
                    {data.hosts.map((h) => (
                        <tr key={h.host} className="border-t border-slate-800">
                            <td className="py-2 pr-4">{h.host}</td>
                            <td className="py-2 pr-4">{h.events}</td>
                            <td className="py-2 pr-4">{h.failures}</td>
                            <td className="py-2 pr-4">{h.successes}</td>
                            <td className="py-2 pr-4">{h.users}</td>
                            <td className="py-2 pr-4">{h.source_ips}</td>
                            <td className="py-2 pr-4">{fmt(h.first_seen)}</td>
                            <td className="py-2 pr-4">{fmt(h.last_seen)}</td>
                        </tr>
                    ))}
                </tbody>
            </table>

            <h2 className="mt-8 mb-4 text-2xl font-bold">Users</h2>
            <table className="w-full text-sm">
                <thead>
                    <tr className="text-left text-slate-400">
                        <th className="py-2 pr-4">User</th>
                        <th className="py-2 pr-4">Events</th>
                        <th className="py-2 pr-4">Failures</th>
                        <th className="py-2 pr-4">Successes</th>
                        <th className="py-2 pr-4">Source IPs</th>
                        <th className="py-2 pr-4">Hosts</th>
                        <th className="py-2 pr-4">First seen</th>
                        <th className="py-2 pr-4">Last seen</th>
                    </tr>
                </thead>
                <tbody>
                    {data.users.map((u) => (
                        <tr key={u.username} className="border-t border-slate-800">
                            <td className="py-2 pr-4">{u.username}</td>
                            <td className="py-2 pr-4">{u.events}</td>
                            <td className="py-2 pr-4">{u.failures}</td>
                            <td className="py-2 pr-4">{u.successes}</td>
                            <td className="py-2 pr-4">{u.source_ips}</td>
                            <td className="py-2 pr-4">{u.hosts}</td>
                            <td className="py-2 pr-4">{fmt(u.first_seen)}</td>
                            <td className="py-2 pr-4">{fmt(u.last_seen)}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

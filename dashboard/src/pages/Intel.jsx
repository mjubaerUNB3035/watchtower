import { useEffect, useState } from "react";
import { getIntel } from "../api";

export default function Intel() {
    const [records, setRecords] = useState([]);

    useEffect(() => {
        getIntel().then(setRecords);
    }, []);

    return (
        <div>
            <h1>Threat Intel</h1>
            {records.map((record) => (
                <div key={record.ip} className="rounded border p-4 mb-4">
                    <h2>{record.ip}</h2>
                    <p>Score: {record.score}</p>
                    <p>Reports: {record.reports}</p>
                    <p>Country: {record.country || "None"}</p>
                    <p>ISP: {record.isp || "None"}</p>
                    <p>Checked: {new Date(record.checked_at).toLocaleString()}</p>
                </div>
            ))}
        </div>
    );
}
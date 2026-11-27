import { useEffect, useState } from "react";
import { getUpdates } from "../api";

export default function Updates() {
    const [updates, setUpdates] = useState([]);

    useEffect(() => {
        getUpdates().then(setUpdates);
    }, []);

    return (
        <div>
            <h1>Updates</h1>
            {updates.map((update) => (
                <div key={update.date + update.title} className="rounded border p-4 mb-4">
                    <p>{update.date}</p>
                    <h2>{update.title}</h2>
                    <p>{update.text}</p>
                </div>
            ))}
        </div>
    );
}
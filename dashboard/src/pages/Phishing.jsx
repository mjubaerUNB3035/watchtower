import { useEffect, useState } from "react";
import { getPhishing } from "../api";

// verdict color
function verdictClass(verdict) {
    if (verdict === "phishing") return "text-red-600";
    if (verdict === "suspicious") return "text-amber-600";
    return "text-green-600";
}

// Phishing page
export default function Phishing() {
    const [reports, setReports] = useState([]);

    useEffect(() => {
        getPhishing().then(setReports);
    }, []);

    return (
        <div className="space-y-4">
            {reports.map((report) => (
                <div key={report.id} className="border rounded p-4">
                    <h2 className="font-semibold">{report.subject}</h2>
                    <p className="text-sm text-gray-500">
                        {report.sender_name} ({report.sender})
                    </p>
                    <p className={verdictClass(report.verdict)}>
                        {report.verdict || "not judged"} ({report.confidence})
                    </p>
                    <p>{report.summary}</p>
                    <ul className="list-disc ml-5">
                        {report.findings.map((finding, index) => (
                            <li key={index}>
                                {finding.check}: {finding.detail}
                            </li>
                        ))}
                    </ul>
                </div>
            ))}
        </div>
    );
}

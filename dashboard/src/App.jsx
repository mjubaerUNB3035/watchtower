import { useState } from "react";
import Overview from "./pages/Overview";
import AlertDetail from "./pages/AlertDetail";
import AlertQueue from "./pages/AlertQueue";
import Incidents from "./pages/Incidents";
import ShiftLog from "./pages/ShiftLog";
import Hosts from "./pages/Hosts";

// sidebar pages
const PAGES = [
    { id: "overview", label: "Overview" },
    { id: "queue", label: "Alert queue" },
    { id: "incidents", label: "Incidents" },
    { id: "shift", label: "Shift log" },
    { id: "hosts", label: "Hosts and users" },
];

export default function App() {
    // current page, and the alert opened from the queue
    const [page, setPage] = useState("overview");
    const [selectedAlert, setSelectedAlert] = useState(null);

    // open one alert in the detail page
    function openAlert(id) {
        setSelectedAlert(id);
        setPage("detail");
    }

    return (
        <div className="flex min-h-screen bg-slate-950 text-slate-100">
            <aside className="w-56 shrink-0 border-r border-slate-800 p-4">
                <h1 className="mb-6 text-xl font-bold">WatchTower</h1>
                <nav className="space-y-1">
                    {PAGES.map((p) => (
                        <button
                            key={p.id}
                            onClick={() => setPage(p.id)}
                            className={`block w-full rounded px-3 py-2 text-left ${page === p.id
                                ? "bg-slate-800 font-semibold"
                                : "hover:bg-slate-900"
                                }`}
                        >
                            {p.label}
                        </button>
                    ))}
                </nav>
            </aside>
            <main className="flex-1 p-6">
                {/* overview page */}
                {page === "overview" && <Overview />}
                {/* alert queue page */}
                {page === "queue" && <AlertQueue onSelect={openAlert} />}
                {/* alert detail page */}
                {page === "detail" && (
                    <AlertDetail
                        alertId={selectedAlert}
                        onBack={() => setPage("queue")}
                    />
                )}
                {/* incidents page */}
                {page === "incidents" && <Incidents />}
                {/* shift log page */}
                {page === "shift" && <ShiftLog />}
                {/* hosts and users page */}
                {page === "hosts" && <Hosts />}
            </main>
        </div>
    );
}

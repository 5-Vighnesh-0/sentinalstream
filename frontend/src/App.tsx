import { useCallback, useState } from "react";
import AlertFeed, { type AlertItem } from "./components/AlertFeed";
import AttackDistribution from "./components/AttackDistribution";
import Banners from "./components/Banners";
import PCAPUpload from "./components/PCAPUpload";
import TrafficChart, { type TrafficPoint } from "./components/TrafficChart";
import { API_URL, TRAFFIC_WINDOW_S, WS_URL } from "./config";
import { useWebSocket } from "./useWebSocket";

const KEPT_ALERTS = 1000; // in memory; the feed renders at most 200

/** Newest activity first; an aggregated update (same id, higher count) replaces the old copy. */
function upsert(list: AlertItem[], incoming: AlertItem[]): AlertItem[] {
  const ids = new Set(incoming.map((a) => a.id));
  return [...incoming, ...list.filter((a) => !ids.has(a.id))].slice(0, KEPT_ALERTS);
}

export default function App() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [traffic, setTraffic] = useState<TrafficPoint[]>([]);
  const [iface, setIface] = useState<string | null>(null);
  const [modelLoaded, setModelLoaded] = useState<boolean | null>(null);
  const [batches, setBatches] = useState<Record<number, string>>({});
  const [view, setView] = useState<number | null>(null); // null = live traffic, else an upload batch id

  const loadAlerts = useCallback(async (batchId: number | null) => {
    const query = batchId === null ? "limit=200" : `limit=500&batch_id=${batchId}`;
    try {
      const page = await (await fetch(`${API_URL}/alerts?${query}`)).json();
      setAlerts((prev) => upsert(prev, page.items));
    } catch {
      // the connection banner already says the backend is unreachable
    }
  }, []);

  const onOpen = useCallback(() => {
    fetch(`${API_URL}/health`).then((r) => r.json()).then((h) => setModelLoaded(h.model_loaded)).catch(() => {});
    loadAlerts(null); // catch up on anything missed while disconnected
  }, [loadAlerts]);

  const onMessage = useCallback((message: { type: string; data: any }) => {
    if (message.type === "alert") {
      setAlerts((prev) => upsert(prev, [message.data]));
    } else if (message.type === "stats") {
      setIface(message.data.iface);
      const time = new Date(message.data.timestamp).toLocaleTimeString();
      setTraffic((prev) => [...prev, { time, pps: message.data.packets_per_s }].slice(-TRAFFIC_WINDOW_S));
    } else if (message.type === "batch") {
      setBatches((prev) => ({ ...prev, [message.data.batch_id]: message.data.status }));
    }
  }, []);

  const status = useWebSocket(WS_URL, { onMessage, onOpen });
  const visible = alerts.filter((a) => a.batch_id === view);

  function viewBatch(batchId: number | null) {
    setView(batchId);
    if (batchId !== null) loadAlerts(batchId);
  }

  return (
    <div className="mx-auto max-w-7xl space-y-4 p-4 sm:p-6">
      <header className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-2xl font-semibold">SentinelStream</h1>
        <p className="text-sm text-muted">
          {status === "open" ? "Connected" : status === "connecting" ? "Connecting…" : "Reconnecting…"}
          {iface && ` · capturing on ${iface}`}
        </p>
      </header>
      <Banners status={status} iface={iface} modelLoaded={modelLoaded} />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-2">
          <label className="flex items-center gap-2 text-sm text-muted">
            View
            <select
              className="rounded border border-hairline bg-surface px-2 py-1 text-ink"
              value={view ?? "live"}
              onChange={(e) => viewBatch(e.target.value === "live" ? null : Number(e.target.value))}
            >
              <option value="live">Live traffic</option>
              {Object.keys(batches).map((id) => (
                <option key={id} value={id}>Upload {id}</option>
              ))}
            </select>
          </label>
          <AlertFeed alerts={visible} captureTime={view !== null} />
        </div>
        <div className="space-y-4">
          <TrafficChart points={traffic} />
          <AttackDistribution alerts={visible} />
          <PCAPUpload
            batches={batches}
            onUploaded={(id) => setBatches((prev) => ({ ...prev, [id]: prev[id] ?? "pending" }))}
            onView={viewBatch}
          />
        </div>
      </div>
    </div>
  );
}

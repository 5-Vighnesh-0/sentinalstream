import { useState } from "react";
import { API_URL } from "../config";
import { authHeader } from "../token";

const ERRORS: Record<number, string> = {
  403: "The backend refused the upload. Open the dashboard at http://localhost:3000.",
  413: "That file is larger than 50 MB.",
  429: "Three uploads are already in progress. Try again when one finishes.",
};

type Props = {
  batches: Record<number, string>;
  onUploaded: (batchId: number) => void;
  onView: (batchId: number) => void;
  token: string;
  onRejected: () => void;
};

export default function PCAPUpload({ batches, onUploaded, onView, token, onRejected }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function upload(event: React.FormEvent) {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError("");
    try {
      const body = new FormData();
      body.append("file", file);
      // The custom header makes the browser send a CORS preflight, which the backend checks (CSRF protection).
      const response = await fetch(`${API_URL}/upload-pcap`, { method: "POST", body, headers: { ...authHeader(token), "X-Sentinel-Upload": "1" } });
      if (response.status === 401) {
        onRejected();
        setError("The backend rejected the dashboard token.");
        return;
      }
      const data = await response.json().catch(() => ({}));
      if (response.ok) {
        onUploaded(data.batch_id);
        setFile(null);
      } else {
        setError(ERRORS[response.status] ?? data.detail ?? `Upload failed (HTTP ${response.status}).`);
      }
    } catch {
      setError("Can't reach the backend at localhost:8000.");
    } finally {
      setBusy(false);
    }
  }

  const ids = Object.keys(batches).map(Number).sort((a, b) => b - a);
  return (
    <section className="rounded-lg border border-hairline bg-surface p-4">
      <h2 className="mb-1 text-lg font-semibold">Analyse a capture file</h2>
      <p className="mb-3 text-sm text-muted">A .pcap or .pcapng file up to 50 MB. Its alerts appear in their own view, apart from live traffic.</p>
      <form onSubmit={upload} className="flex flex-wrap items-center gap-2">
        <input
          type="file"
          accept=".pcap,.pcapng"
          aria-label="Capture file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="min-w-0 flex-1 text-sm file:mr-2 file:rounded file:border file:border-hairline file:bg-page file:px-2 file:py-1"
        />
        <button type="submit" disabled={!file || busy} className="rounded bg-ink px-3 py-1.5 text-sm text-white disabled:opacity-40">
          {busy ? "Uploading…" : "Analyse"}
        </button>
      </form>
      {error && <p role="alert" className="mt-2 text-sm text-sev-high">{error}</p>}
      {ids.length > 0 && (
        <ul className="mt-3 space-y-1 text-sm">
          {ids.map((id) => (
            <li key={id} className="flex items-center justify-between">
              <span>Upload {id}: {batches[id]}</span>
              {batches[id] === "done" && (
                <button type="button" className="text-traffic underline" onClick={() => onView(id)}>View alerts</button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

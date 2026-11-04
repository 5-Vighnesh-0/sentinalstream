import { LoaderCircle } from "lucide-react";
import { useRef, useState } from "react";
import { API_URL } from "../config";
import { authHeader } from "../token";

const MAX_BYTES = 50 * 1024 * 1024; // the backend's cap (docs/API_SPEC.md)

const ERRORS: Record<number, string> = {
  403: "The backend refused the upload. Open the dashboard at http://localhost:3000.",
  413: "That file is larger than 50 MB.",
  429: "Three uploads are already in progress. Try again when one finishes.",
};

export type Batch = { name: string; status: string };

type Props = {
  batches: Record<number, Batch>;
  onUploaded: (batchId: number, name: string) => void;
  token: string;
  onRejected: () => void;
};

/** Checked here first so a wrong file fails at once, not after a 50 MB upload. */
export function checkFile(file: File): string {
  if (!/\.pcap(ng)?$/i.test(file.name)) return "Choose a .pcap or .pcapng file.";
  if (file.size > MAX_BYTES) return "That file is larger than 50 MB.";
  return "";
}

const STATUS: Record<string, string> = { pending: "Queued", processing: "Parsing in sandbox", done: "Done: open its tab above", failed: "Failed: the file could not be parsed" };

export default function PCAPUpload({ batches, onUploaded, token, onRejected }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  function choose(f: File | null) {
    setFile(f);
    setError(f ? checkFile(f) : "");
  }

  async function upload(event: React.FormEvent) {
    event.preventDefault();
    if (!file || checkFile(file)) return;
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
        onUploaded(data.batch_id, file.name);
        setFile(null);
        if (input.current) input.current.value = "";
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
    <section
      className={`ink-panel p-4 ${dragging ? "bg-accent-tint" : "bg-surface"}`}
      aria-labelledby="upload-heading"
      // the whole panel takes a dropped file: no dashed drop box needed
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDragging(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        choose(e.dataTransfer.files[0] ?? null);
      }}
    >
      <h2 id="upload-heading" className="text-lg font-semibold">Analyse a capture file</h2>
      <p className="mt-1 text-sm text-muted">
        {dragging ? "Drop it here to choose it." : "A .pcap or .pcapng up to 50 MB, or drop one on this panel. Its alerts open in their own tab."}
      </p>
      <form onSubmit={upload} className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2">
        <label className="min-h-9 cursor-pointer rounded border border-ink px-3 py-1.5 text-sm font-medium hover:bg-sunk has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-accent">
          Choose file
          <input ref={input} type="file" accept=".pcap,.pcapng" aria-label="Capture file" className="sr-only" onChange={(e) => choose(e.target.files?.[0] ?? null)} />
        </label>
        <span className={`min-w-0 flex-1 truncate text-sm ${file ? "font-mono text-[13px]" : "text-muted"}`} title={file?.name}>
          {file ? file.name : "No file chosen"}
        </span>
        {file && !error && (
          <button type="submit" disabled={busy} className="ink-btn inline-flex min-h-9 items-center gap-2 rounded px-4 text-sm font-semibold">
            {busy && <LoaderCircle aria-hidden size={16} className="animate-spin motion-reduce:animate-none" />}
            {busy ? "Uploading…" : "Analyse"}
          </button>
        )}
      </form>
      {error && <p role="alert" className="mt-2 text-sm text-sev-high-ink">{error}</p>}
      {ids.length > 0 && (
        <ul className="mt-3 space-y-1 border-t border-row pt-3 text-sm">
          {ids.map((id) => (
            <li key={id} className="flex items-baseline justify-between gap-3">
              <span className="truncate font-mono text-[13px]" title={batches[id].name}>{batches[id].name}</span>
              <span className={`shrink-0 ${batches[id].status === "failed" ? "font-medium text-sev-high-ink" : "text-muted"}`}>
                {STATUS[batches[id].status] ?? batches[id].status}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

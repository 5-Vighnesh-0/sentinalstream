import { FileUp, LoaderCircle } from "lucide-react";
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
    <section className="rounded-lg border border-hairline bg-surface p-4" aria-labelledby="upload-heading">
      <h2 id="upload-heading" className="text-base font-semibold">Analyse a capture file</h2>
      <p className="mt-1 text-sm text-muted">Its alerts open in their own tab, apart from live traffic.</p>
      <form onSubmit={upload} className="mt-3 space-y-3">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            choose(e.dataTransfer.files[0] ?? null);
          }}
          className={`flex flex-col items-center gap-2 rounded-md border-2 border-dashed px-4 py-5 text-center ${dragging ? "border-accent bg-accent-tint" : "border-edge"}`}
        >
          <FileUp aria-hidden size={22} className="text-muted" />
          <p className="text-sm">{file ? <span className="font-mono">{file.name}</span> : "Drop a .pcap or .pcapng here, up to 50 MB"}</p>
          <label className="cursor-pointer rounded border border-edge bg-surface px-3 py-1.5 text-sm font-medium text-accent hover:bg-accent-tint has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent">
            Browse files
            <input ref={input} type="file" accept=".pcap,.pcapng" aria-label="Capture file" className="sr-only" onChange={(e) => choose(e.target.files?.[0] ?? null)} />
          </label>
        </div>
        <button
          type="submit"
          disabled={!file || !!error || busy}
          className="inline-flex w-full items-center justify-center gap-2 rounded bg-accent px-3 py-2 text-sm font-semibold text-white hover:bg-accent/90 disabled:bg-sunk disabled:text-muted"
        >
          {busy && <LoaderCircle aria-hidden size={16} className="animate-spin motion-reduce:animate-none" />}
          {busy ? "Uploading…" : "Analyse"}
        </button>
      </form>
      {error && <p role="alert" className="mt-2 text-sm text-sev-high-ink">{error}</p>}
      {ids.length > 0 && (
        <ul className="mt-3 space-y-1 border-t border-hairline pt-3 text-sm">
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

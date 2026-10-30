import { useState } from "react";
import { TOKEN_PATTERN } from "../token";

export default function TokenForm({ onSave, rejected }: { onSave: (token: string) => void; rejected: boolean }) {
  const [value, setValue] = useState("");
  const [malformed, setMalformed] = useState(false);
  return (
    <section className="rounded-lg border border-hairline bg-surface p-6">
      <h2 className="text-base font-semibold">Paste the dashboard token</h2>
      <p className="mt-1 text-sm text-muted">
        The backend prints it when it starts and keeps it in <code className="font-mono text-[13px]">data/api-token</code> (with Docker: <code className="font-mono text-[13px]">docker compose logs backend</code>).
      </p>
      <p role="alert" className="mt-2 min-h-5 text-sm font-medium text-sev-high-ink">
        {malformed ? "That doesn't look like a dashboard token." : rejected ? "The backend rejected that token." : ""}
      </p>
      <form
        className="mt-3 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          const token = value.trim();
          if (!token) return;
          setMalformed(!TOKEN_PATTERN.test(token));
          if (TOKEN_PATTERN.test(token)) onSave(token);
        }}
      >
        <label className="sr-only" htmlFor="dashboard-token">Dashboard token</label>
        <input
          id="dashboard-token"
          type="password"
          autoComplete="off"
          autoFocus
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className="min-w-0 flex-1 rounded border border-edge px-3 py-2 font-mono text-sm"
        />
        <button type="submit" className="rounded bg-accent px-4 py-2 text-sm font-semibold text-white hover:bg-accent/90">Save</button>
      </form>
    </section>
  );
}

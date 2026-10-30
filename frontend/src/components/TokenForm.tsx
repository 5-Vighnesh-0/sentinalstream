import { useState } from "react";
import { TOKEN_PATTERN } from "../token";

export default function TokenForm({ onSave, rejected }: { onSave: (token: string) => void; rejected: boolean }) {
  const [value, setValue] = useState("");
  const [malformed, setMalformed] = useState(false);
  return (
    <section className="rounded-lg border border-hairline bg-surface p-4">
      <h2 className="text-lg font-semibold">Paste the dashboard token</h2>
      <p className="mt-1 text-sm text-muted">
        The backend prints it when it starts and keeps it in data/api-token (with Docker: docker compose logs backend).
      </p>
      <p role="alert" className="mt-1 text-sm text-sev-high">
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
          className="min-w-0 flex-1 rounded border border-hairline px-2 py-1 text-sm"
        />
        <button type="submit" className="rounded bg-ink px-3 py-1.5 text-sm text-white">Save</button>
      </form>
    </section>
  );
}

import { TriangleAlert } from "lucide-react";
import { useState } from "react";
import type { RuleIn } from "../api";
import { endpoint, type AlertItem } from "./AlertFeed";
import { typeLabel } from "./Level";

type Props = { alert: AlertItem; onSave: (rule: RuleIn) => Promise<void>; onCancel: () => void };

const FIELDS = ["src_ip", "dst_ip", "dst_port", "attack_type"] as const;
const LABEL = { src_ip: "Source IP", dst_ip: "Destination IP", dst_port: "Destination port", attack_type: "Attack type" };

/** "Mute alerts like this": each field is this alert's value (default) or "any". A rule of all "any" would hide everything,
 *  so Save stays disabled; "any" attack type is allowed but warned about, because it can hide real attacks. */
export default function MuteEditor({ alert, onSave, onCancel }: Props) {
  const [any, setAny] = useState<Record<(typeof FIELDS)[number], boolean>>({ src_ip: false, dst_ip: false, dst_port: false, attack_type: false });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const allAny = FIELDS.every((f) => any[f]);
  const value = (f: (typeof FIELDS)[number]) => (f === "attack_type" ? typeLabel(alert.attack_type) : String(alert[f]));

  async function save() {
    setBusy(true);
    setError("");
    try {
      await onSave(Object.fromEntries(FIELDS.filter((f) => !any[f]).map((f) => [f, alert[f]])) as RuleIn);
    } catch {
      setError("The backend refused the rule. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <fieldset className="space-y-3 rounded-md border border-hairline p-3">
      <legend className="px-1 text-sm font-semibold">Mute alerts like this</legend>
      <p className="text-xs text-muted">
        Muted alerts are still stored and counted; delete the rule to bring them back. Matching {endpoint(alert.dst_ip, alert.dst_port)} keeps the source port out: it changes on every connection.
      </p>
      {FIELDS.map((f) => (
        <div key={f} role="radiogroup" aria-label={LABEL[f]} className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
          <span className="w-36 text-muted">{LABEL[f]}</span>
          <label className="inline-flex items-center gap-1.5">
            <input type="radio" name={`mute-${f}`} checked={!any[f]} onChange={() => setAny({ ...any, [f]: false })} />
            <span className="font-mono text-[13px]">{value(f)}</span>
          </label>
          <label className="inline-flex items-center gap-1.5">
            <input type="radio" name={`mute-${f}`} checked={any[f]} onChange={() => setAny({ ...any, [f]: true })} />
            any
          </label>
        </div>
      ))}
      {any.attack_type && !allAny && (
        <p className="flex items-center gap-1.5 text-sm text-sev-medium-ink">
          <TriangleAlert aria-hidden size={14} /> Any attack type can hide real attacks from these addresses.
        </p>
      )}
      <div className="flex items-center gap-2">
        <button type="button" disabled={allAny || busy} onClick={save} className="rounded bg-accent px-3 py-1.5 text-sm font-semibold text-white hover:bg-accent/90 disabled:bg-sunk disabled:text-muted">
          {busy ? "Saving…" : "Mute"}
        </button>
        <button type="button" onClick={onCancel} className="rounded px-3 py-1.5 text-sm font-medium text-accent hover:bg-accent-tint">Cancel</button>
        {allAny && <span className="text-sm text-muted">Keep at least one field: a rule of all "any" would mute everything.</span>}
      </div>
      <p role="alert" className="text-sm text-sev-high-ink empty:hidden">{error}</p>
    </fieldset>
  );
}

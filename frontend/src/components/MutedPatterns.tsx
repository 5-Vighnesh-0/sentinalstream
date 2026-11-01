import { X } from "lucide-react";
import type { Rule } from "../api";
import { endpoint } from "./AlertFeed";
import { typeLabel } from "./Level";

/** One rule in words, e.g. "Anomaly from 127.0.0.1 to 127.0.0.1:42361"; "any" fills a wildcard field. */
export function describe(rule: Rule): string {
  const type = rule.attack_type ? typeLabel(rule.attack_type) : "Any attack type";
  const to = rule.dst_ip ? (rule.dst_port !== null ? endpoint(rule.dst_ip, rule.dst_port) : `${rule.dst_ip} (any port)`) : rule.dst_port !== null ? `any address, port ${rule.dst_port}` : "anywhere";
  return `${type} from ${rule.src_ip ?? "anywhere"} to ${to}`;
}

type Props = { rules: Rule[]; onDelete: (id: number) => Promise<void> };

/** The mute rules in force; deleting one unmutes its alerts at once (they were never deleted). */
export default function MutedPatterns({ rules, onDelete }: Props) {
  if (rules.length === 0) return null;
  return (
    <section className="rounded-lg border border-hairline bg-surface p-4" aria-labelledby="muted-heading">
      <h2 id="muted-heading" className="text-lg font-semibold">Muted patterns</h2>
      <p className="mt-1 text-sm text-muted">Matching alerts are stored and counted, but hidden from the feed.</p>
      <ul className="mt-3 divide-y divide-hairline border-t border-hairline">
        {rules.map((rule) => (
          <li key={rule.id} className="flex items-center justify-between gap-3 py-2 text-sm">
            <span className="min-w-0 break-words">{describe(rule)}</span>
            <button
              type="button"
              onClick={() => onDelete(rule.id)}
              aria-label={`Delete rule: ${describe(rule)}`}
              className="inline-flex size-8 shrink-0 items-center justify-center rounded text-muted hover:bg-sunk hover:text-ink"
            >
              <X aria-hidden size={16} />
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

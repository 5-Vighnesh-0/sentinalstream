import type { AlertItem } from "./components/AlertFeed";
import { API_URL } from "./config";
import { authHeader } from "./token";

export type Rule = { id: number; src_ip: string | null; dst_ip: string | null; dst_port: number | null; attack_type: string | null; created_at: string };
export type RuleIn = Partial<Pick<Rule, "src_ip" | "dst_ip" | "dst_port" | "attack_type">>;
export type Upload = { id: number; filename: string; uploaded_at: string; status: string };

async function call(token: string, path: string, init: RequestInit = {}) {
  const headers = { ...authHeader(token), ...(init.body ? { "Content-Type": "application/json" } : {}) };
  const response = await fetch(`${API_URL}${path}`, { ...init, headers });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.status === 204 ? null : response.json();
}

export const ackAlert = (token: string, id: string, acknowledged: boolean): Promise<AlertItem> =>
  call(token, `/alerts/${encodeURIComponent(id)}/ack`, { method: "PUT", body: JSON.stringify({ acknowledged }) });
export const listRules = (token: string): Promise<Rule[]> => call(token, "/suppressions");
export const createRule = (token: string, rule: RuleIn): Promise<Rule> =>
  call(token, "/suppressions", { method: "POST", body: JSON.stringify(rule) });
export const deleteRule = (token: string, id: number) => call(token, `/suppressions/${id}`, { method: "DELETE" });
export const listUploads = (token: string): Promise<Upload[]> => call(token, "/uploads");

/** Same rule as the API (backend/api/suppressions.py): every non-null field must match; lowest id wins.
 *  Mirrored here so alerts already loaded update the moment a rule is created or deleted. */
export function mutedBy(rules: Rule[], alert: AlertItem): number | null {
  const fields = ["src_ip", "dst_ip", "dst_port", "attack_type"] as const;
  return rules.find((r) => fields.every((f) => r[f] === null || r[f] === alert[f]))?.id ?? null;
}

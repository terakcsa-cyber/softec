import { apiFetch } from "./api-fetch";
import type { VocAlertCondition, VocAlertRuleRow, VocHandoverReport, VocKpiSnapshot } from "./voc-shift-client";

async function readApiError(res: Response, fallback: string): Promise<string> {
  try {
    const body = (await res.json()) as { message?: string | string[] };
    const msg = body.message;
    if (Array.isArray(msg)) return msg.join(", ");
    if (typeof msg === "string" && msg.trim()) return msg;
  } catch {
    // ignore
  }
  return `${fallback} (${res.status})`;
}

export async function fetchVocKpis(hours = 8): Promise<VocKpiSnapshot> {
  const url = new URL("/api/voc/kpis", window.location.origin);
  url.searchParams.set("hours", String(hours));
  const res = await apiFetch(url.toString(), { cache: "no-store" });
  if (!res.ok) throw new Error(`VOC KPI (${res.status})`);
  return (await res.json()) as VocKpiSnapshot;
}

export async function createVocHandover(body: {
  hours?: number;
  notes?: string | null;
}): Promise<VocHandoverReport> {
  const res = await apiFetch("/api/voc/handover", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось создать handover"));
  return (await res.json()) as VocHandoverReport;
}

export async function fetchVocAlertRules(): Promise<VocAlertRuleRow[]> {
  const res = await apiFetch("/api/voc/alert-rules", { cache: "no-store" });
  if (!res.ok) throw new Error(`VOC alert rules (${res.status})`);
  return (await res.json()) as VocAlertRuleRow[];
}

export async function addVocAlertRule(body: {
  name: string;
  condition: VocAlertCondition;
  channel?: "telegram" | "webhook";
  webhookUrl?: string | null;
}): Promise<{ rules: VocAlertRuleRow[] }> {
  const res = await apiFetch("/api/voc/alert-rules", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось добавить правило"));
  return (await res.json()) as { rules: VocAlertRuleRow[] };
}

export async function patchVocAlertRule(
  id: string,
  body: { active?: boolean; name?: string; webhookUrl?: string | null }
): Promise<{ rules: VocAlertRuleRow[] }> {
  const res = await apiFetch(`/api/voc/alert-rules/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось обновить правило"));
  return (await res.json()) as { rules: VocAlertRuleRow[] };
}

export async function deleteVocAlertRule(id: string): Promise<{ rules: VocAlertRuleRow[] }> {
  const res = await apiFetch(`/api/voc/alert-rules/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось удалить правило"));
  return (await res.json()) as { rules: VocAlertRuleRow[] };
}

export async function evaluateVocAlerts(): Promise<{ fired: number; results: unknown[] }> {
  const res = await apiFetch("/api/voc/alerts/evaluate", { method: "POST" });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось проверить алерты"));
  return (await res.json()) as { fired: number; results: unknown[] };
}

import { apiFetch } from "./api-fetch";

export type VocWatchlistKind = "vendor" | "product" | "keyword";

export type VocWatchlistRule = {
  id: string;
  kind: VocWatchlistKind;
  value: string;
  label: string;
  active: boolean;
};

async function readApiError(res: Response, fallback: string): Promise<string> {
  try {
    const body = (await res.json()) as { message?: string | string[]; error?: string };
    const msg = body.message;
    if (Array.isArray(msg)) return msg.join(", ");
    if (typeof msg === "string" && msg.trim()) return msg;
    if (typeof body.error === "string" && body.error.trim()) return body.error;
  } catch {
    // ignore
  }
  return `${fallback} (${res.status})`;
}

export async function fetchVocWatchlist(): Promise<VocWatchlistRule[]> {
  const res = await apiFetch("/api/voc/watchlist", { cache: "no-store" });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось загрузить watchlist"));
  return (await res.json()) as VocWatchlistRule[];
}

export async function addVocWatchlist(body: {
  kind: VocWatchlistKind;
  value: string;
  label?: string;
}): Promise<VocWatchlistRule> {
  const res = await apiFetch("/api/voc/watchlist", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось добавить в watchlist"));
  return (await res.json()) as VocWatchlistRule;
}

export async function patchVocWatchlist(id: string, body: { active?: boolean; label?: string }) {
  const res = await apiFetch(`/api/voc/watchlist/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось обновить watchlist"));
  return (await res.json()) as VocWatchlistRule;
}

export async function deleteVocWatchlist(id: string) {
  const res = await apiFetch(`/api/voc/watchlist/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось удалить из watchlist"));
  return (await res.json()) as { ok: boolean };
}

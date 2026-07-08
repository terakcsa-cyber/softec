import { apiFetch } from "./api-fetch";

export type VocSource = "cve" | "bdu" | "tg";
export type VocTriageStatus = "open" | "claimed" | "done" | "dismissed";
export type VocPriority = "p1" | "p2" | "p3" | "p4";

export type VocQueueItem = {
  refKey: string;
  source: VocSource;
  refId: string;
  vocScore: number;
  vocPriority: VocPriority;
  vocReasons: string[];
  title: string;
  subtitle: string;
  publishedAt: string | null;
  status: VocTriageStatus;
  claimedByEmail: string | null;
  updatedAt: string | null;
  payload: Record<string, unknown>;
  caseId?: string | null;
  caseStatus?: string | null;
  assigneeEmail?: string | null;
  slaDueAt?: string | null;
  slaBreached?: boolean;
  linkedRefsCount?: number;
  taskId?: string | null;
};

export type VocQueueResponse = {
  items: VocQueueItem[];
  stats: Record<string, number>;
};

export async function fetchVocQueue(params?: {
  source?: string;
  status?: string;
  limit?: number;
}): Promise<VocQueueResponse> {
  const url = new URL("/api/voc/queue", window.location.origin);
  if (params?.source) url.searchParams.set("source", params.source);
  if (params?.status) url.searchParams.set("status", params.status);
  if (params?.limit) url.searchParams.set("limit", String(params.limit));
  const res = await apiFetch(url.toString(), { cache: "no-store" });
  if (!res.ok) throw new Error(`VOC queue (${res.status})`);
  return (await res.json()) as VocQueueResponse;
}

export type VocTriageRow = {
  refKey: string;
  status: VocTriageStatus;
  claimedByEmail: string | null;
  updatedAt: string | null;
};

export async function fetchVocTriageBySource(source: VocSource, limit = 200): Promise<VocTriageRow[]> {
  const url = new URL("/api/voc/triage", window.location.origin);
  url.searchParams.set("source", source);
  url.searchParams.set("limit", String(limit));
  const res = await apiFetch(url.toString(), { cache: "no-store" });
  if (!res.ok) throw new Error(`VOC triage (${res.status})`);
  return (await res.json()) as VocTriageRow[];
}

export async function fetchVocTriageAll(limit = 500): Promise<VocTriageRow[]> {
  const url = new URL("/api/voc/triage", window.location.origin);
  url.searchParams.set("source", "all");
  url.searchParams.set("limit", String(limit));
  const res = await apiFetch(url.toString(), { cache: "no-store" });
  if (!res.ok) throw new Error(`VOC triage (${res.status})`);
  return (await res.json()) as VocTriageRow[];
}

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

export async function patchVocTriage(body: {
  refKey: string;
  source: VocSource;
  refId: string;
  status: VocTriageStatus;
  title?: string;
  vocScore?: number;
  vocPriority?: VocPriority;
  vocReasons?: string[];
  meta?: Record<string, unknown>;
}): Promise<{ ok: boolean; refKey: string; status: VocTriageStatus }> {
  const res = await apiFetch("/api/voc/triage", {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось обновить triage"));
  return (await res.json()) as { ok: boolean; refKey: string; status: VocTriageStatus };
}

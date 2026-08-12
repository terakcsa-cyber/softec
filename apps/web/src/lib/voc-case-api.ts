import { apiFetch } from "./api-fetch";
import type { VocPriority, VocSource } from "./voc-api";

export type VocCaseStatus = "open" | "in_progress" | "resolved" | "cancelled";

export type VocCaseRef = {
  refKey: string;
  source: VocSource;
  refId: string;
  addedAt: string;
};

export type VocCaseEvidenceRow = {
  id: string;
  body: string;
  url: string | null;
  authorEmail: string | null;
  createdAt: string;
};

export type VocCaseRow = {
  id: string;
  title: string;
  status: VocCaseStatus;
  dedupKey: string;
  primaryRefKey: string;
  assigneeUserId: string | null;
  assigneeEmail: string | null;
  slaDueAt: string | null;
  vocPriority: VocPriority;
  taskId: string | null;
  createdByEmail: string | null;
  createdAt: string;
  updatedAt: string;
  refCount: number;
  refs: VocCaseRef[];
  outcome?: import("./voc-verification-client").VocOutcome | null;
  outcomeNotes?: string | null;
  resolvedAt?: string | null;
  playbook?: import("./voc-verification-client").VocPlaybook | null;
  evidence?: VocCaseEvidenceRow[];
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

export async function fetchVocCases(params?: { status?: string; limit?: number }): Promise<VocCaseRow[]> {
  const url = new URL("/api/voc/cases", window.location.origin);
  if (params?.status) url.searchParams.set("status", params.status);
  if (params?.limit) url.searchParams.set("limit", String(params.limit));
  const res = await apiFetch(url.toString(), { cache: "no-store" });
  if (!res.ok) throw new Error(`VOC cases (${res.status})`);
  return (await res.json()) as VocCaseRow[];
}

export async function fetchVocCasesByRef(params: {
  source: VocSource;
  refId: string;
  limit?: number;
}): Promise<VocCaseRow[]> {
  const url = new URL("/api/voc/cases/by-ref", window.location.origin);
  url.searchParams.set("source", params.source);
  url.searchParams.set("refId", params.refId);
  if (params.limit) url.searchParams.set("limit", String(params.limit));
  const res = await apiFetch(url.toString(), { cache: "no-store" });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось загрузить кейсы"));
  return (await res.json()) as VocCaseRow[];
}

export async function createVocCaseFromRef(body: {
  refKey: string;
  source: VocSource;
  refId: string;
  title: string;
  vocPriority?: VocPriority;
  linkedCveIds?: string[];
  vocReasons?: string[];
  subtitle?: string | null;
  tgChannel?: string | null;
  assigneeEmail?: string | null;
  createTask?: boolean;
  vendorKey?: string;
  vendorDisplay?: string;
  productKeyNorm?: string;
  productDisplay?: string;
}): Promise<{ ok: boolean; deduped: boolean; taskId?: string | null; case: VocCaseRow }> {
  const res = await apiFetch("/api/voc/cases", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось создать кейс"));
  return (await res.json()) as { ok: boolean; deduped: boolean; taskId?: string | null; case: VocCaseRow };
}

export async function patchVocCase(
  caseId: string,
  body: {
    status?: VocCaseStatus;
    assigneeEmail?: string | null;
    slaDueAt?: string | null;
    title?: string;
  }
): Promise<{ ok: boolean; case: VocCaseRow }> {
  const res = await apiFetch(`/api/voc/cases/${encodeURIComponent(caseId)}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось обновить кейс"));
  return (await res.json()) as { ok: boolean; case: VocCaseRow };
}

export async function fetchVocCaseDetail(caseId: string): Promise<VocCaseRow> {
  const res = await apiFetch(`/api/voc/cases/${encodeURIComponent(caseId)}`, { cache: "no-store" });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось загрузить кейс"));
  return (await res.json()) as VocCaseRow;
}

export async function addVocCaseEvidence(
  caseId: string,
  body: { body: string; url?: string | null }
): Promise<{ ok: boolean; case: VocCaseRow }> {
  const res = await apiFetch(`/api/voc/cases/${encodeURIComponent(caseId)}/evidence`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось добавить evidence"));
  return (await res.json()) as { ok: boolean; case: VocCaseRow };
}

export async function patchVocCasePlaybook(
  caseId: string,
  body: { stepId: string; done: boolean }
): Promise<{ ok: boolean; case: VocCaseRow }> {
  const res = await apiFetch(`/api/voc/cases/${encodeURIComponent(caseId)}/playbook`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось обновить playbook"));
  return (await res.json()) as { ok: boolean; case: VocCaseRow };
}

export async function resolveVocCase(
  caseId: string,
  body: { outcome: import("./voc-verification-client").VocOutcome; notes?: string | null }
): Promise<{ ok: boolean; case: VocCaseRow }> {
  const res = await apiFetch(`/api/voc/cases/${encodeURIComponent(caseId)}/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось закрыть кейс"));
  return (await res.json()) as { ok: boolean; case: VocCaseRow };
}

export async function regenerateVocCasePlaybook(caseId: string): Promise<{ ok: boolean; case: VocCaseRow }> {
  const res = await apiFetch(`/api/voc/cases/${encodeURIComponent(caseId)}/playbook/regenerate`, {
    method: "POST"
  });
  if (!res.ok) throw new Error(await readApiError(res, "Не удалось перегенерировать playbook"));
  return (await res.json()) as { ok: boolean; case: VocCaseRow };
}

export function buildCaseRefMap(cases: VocCaseRow[]): Map<
  string,
  {
    caseId: string;
    caseStatus: VocCaseStatus;
    assigneeEmail: string | null;
    slaDueAt: string | null;
    taskId: string | null;
    linkedRefsCount: number;
  }
> {
  const map = new Map<
    string,
    {
      caseId: string;
      caseStatus: VocCaseStatus;
      assigneeEmail: string | null;
      slaDueAt: string | null;
      taskId: string | null;
      linkedRefsCount: number;
    }
  >();
  for (const c of cases) {
    for (const ref of c.refs) {
      map.set(ref.refKey, {
        caseId: c.id,
        caseStatus: c.status,
        assigneeEmail: c.assigneeEmail,
        slaDueAt: c.slaDueAt,
        taskId: c.taskId,
        linkedRefsCount: c.refCount
      });
    }
  }
  return map;
}

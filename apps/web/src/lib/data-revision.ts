"use client";

import { useAuth } from "@/contexts/auth-context";
import { apiFetch } from "@/lib/api-fetch";
import { useLivePollInterval } from "@/lib/live-refresh";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

export type DataRevision = {
  cves: string;
  bdu: string;
  voc: string;
  tasks: string;
  threat: string;
  fstec: string;
  patch: string;
  catalog: string;
};

const EMPTY: DataRevision = {
  cves: "",
  bdu: "",
  voc: "",
  tasks: "",
  threat: "",
  fstec: "",
  patch: "",
  catalog: ""
};

async function fetchRevision(): Promise<DataRevision> {
  const res = await apiFetch("/api/stats/revision", { cache: "no-store" });
  if (!res.ok) throw new Error(`revision ${res.status}`);
  return (await res.json()) as DataRevision;
}

function invalidateSlice(
  qc: ReturnType<typeof useQueryClient>,
  prev: DataRevision,
  next: DataRevision
) {
  if (prev.cves !== next.cves) {
    void qc.invalidateQueries({ queryKey: ["cves"] });
    void qc.invalidateQueries({ queryKey: ["cve"] });
  }
  if (prev.bdu !== next.bdu) {
    void qc.invalidateQueries({ queryKey: ["bdu"] });
  }
  if (prev.voc !== next.voc) {
    void qc.invalidateQueries({ queryKey: ["voc"] });
  }
  if (prev.tasks !== next.tasks) {
    void qc.invalidateQueries({ queryKey: ["vuln-tasks"] });
  }
  if (prev.threat !== next.threat) {
    void qc.invalidateQueries({ queryKey: ["stats", "threat-feed"] });
    void qc.invalidateQueries({ queryKey: ["stats", "exploit-radar"] });
  }
  if (prev.fstec !== next.fstec) {
    void qc.invalidateQueries({ queryKey: ["fstec"] });
  }
  if (prev.patch !== next.patch) {
    void qc.invalidateQueries({ queryKey: ["patch"] });
    void qc.invalidateQueries({ queryKey: ["vendor-advisories"] });
  }
  if (prev.catalog !== next.catalog) {
    void qc.invalidateQueries({ queryKey: ["stats", "summary"] });
    void qc.invalidateQueries({ queryKey: ["stats", "vendors"] });
  }
}

/** Cheap poll: refetch lists/cards only when the matching DB watermark moved. */
export function DataRevisionSync() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const pollMs = useLivePollInterval(12_000);
  const prevRef = useRef<DataRevision | null>(null);

  const q = useQuery({
    queryKey: ["data-revision"],
    queryFn: fetchRevision,
    enabled: Boolean(user),
    staleTime: 4_000,
    refetchInterval: pollMs,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: false
  });

  useEffect(() => {
    const next = q.data;
    if (!next) return;
    const prev = prevRef.current;
    prevRef.current = next;
    if (!prev) return;
    invalidateSlice(qc, prev, next);
  }, [q.data, qc]);

  return null;
}

export function useDataRevision(): DataRevision {
  const q = useQuery({
    queryKey: ["data-revision"],
    queryFn: fetchRevision,
    staleTime: 4_000,
    enabled: false
  });
  return q.data ?? EMPTY;
}

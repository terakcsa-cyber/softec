"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  type ReactNode
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  fetchVocTriageAll,
  patchVocTriage,
  type VocSource,
  type VocTriageStatus
} from "./voc-api";
import { clearLegacyProcessedStorage, loadLegacyProcessedRefKeys } from "./voc-triage-migrate";
import { parseVocRefKey } from "./voc-ref-keys";
import { markVocRefClosed, markVocRefOpen } from "./voc-session-closed";
import { useAuth } from "@/contexts/auth-context";

type TriageMap = Map<string, VocTriageStatus>;

type VocTriageContextValue = {
  ready: boolean;
  getStatus: (refKey: string) => VocTriageStatus;
  isDone: (refKey: string) => boolean;
  toggleDone: (refKey: string, opts?: { title?: string }) => void;
  setStatus: (
    refKey: string,
    status: VocTriageStatus,
    opts?: { title?: string; vocScore?: number; vocPriority?: string }
  ) => void;
};

const VocTriageContext = createContext<VocTriageContextValue | null>(null);

function rowsToMap(rows: { refKey: string; status: VocTriageStatus }[]): TriageMap {
  const map = new Map<string, VocTriageStatus>();
  for (const row of rows) map.set(row.refKey, row.status);
  return map;
}

export function VocTriageProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const migratedRef = useRef(false);
  const canWrite = user?.role !== "viewer";

  const triageQuery = useQuery({
    queryKey: ["voc", "triage", "all"],
    queryFn: () => fetchVocTriageAll(600),
    staleTime: 25_000,
    refetchInterval: 90_000
  });

  const statusMap = useMemo(() => rowsToMap(triageQuery.data ?? []), [triageQuery.data]);

  useEffect(() => {
    if (migratedRef.current || !triageQuery.isSuccess) return;
    const legacy = loadLegacyProcessedRefKeys();
    if (!legacy.length) {
      migratedRef.current = true;
      return;
    }
    migratedRef.current = true;
    void (async () => {
      for (const refKey of legacy) {
        if (statusMap.get(refKey) === "done" || statusMap.get(refKey) === "dismissed") continue;
        const parsed = parseVocRefKey(refKey);
        if (!parsed || !canWrite) continue;
        try {
          await patchVocTriage({
            refKey,
            source: parsed.source,
            refId: parsed.refId,
            status: "done",
            title: refKey
          });
        } catch {
          // best-effort import
        }
      }
      clearLegacyProcessedStorage();
      void queryClient.invalidateQueries({ queryKey: ["voc", "triage"] });
      void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
    })();
  }, [canWrite, triageQuery.isSuccess, statusMap, queryClient]);

  const patchMutation = useMutation({
    mutationFn: patchVocTriage,
    onMutate: async (body) => {
      if (body.status === "done" || body.status === "dismissed") markVocRefClosed(body.refKey);
      else markVocRefOpen(body.refKey);
      await queryClient.cancelQueries({ queryKey: ["voc", "triage", "all"] });
      const prev = queryClient.getQueryData<{ refKey: string; status: VocTriageStatus }[]>([
        "voc",
        "triage",
        "all"
      ]);
      queryClient.setQueryData(
        ["voc", "triage", "all"],
        (old: typeof prev) => {
          const rows = [...(old ?? [])];
          const idx = rows.findIndex((r) => r.refKey === body.refKey);
          const row = {
            refKey: body.refKey,
            status: body.status,
            claimedByEmail: body.status === "claimed" ? null : null,
            updatedAt: new Date().toISOString()
          };
          if (idx >= 0) {
            const cur = rows[idx]!;
            rows[idx] = { ...cur, status: body.status };
          } else rows.unshift(row);
          return rows;
        }
      );
      return { prev };
    },
    onError: (_e, vars, ctx) => {
      if (vars.status === "done" || vars.status === "dismissed") markVocRefOpen(vars.refKey);
      if (ctx?.prev) queryClient.setQueryData(["voc", "triage", "all"], ctx.prev);
    },
    onSettled: (_e, err, vars) => {
      void queryClient.invalidateQueries({ queryKey: ["voc", "triage"] });
      if (vars?.status === "done" || vars?.status === "dismissed") return;
      void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
    }
  });

  const patchForKey = useCallback(
    (refKey: string, status: VocTriageStatus, opts?: { title?: string }) => {
      if (!canWrite) return;
      const parsed = parseVocRefKey(refKey);
      if (!parsed) return;
      patchMutation.mutate({
        refKey,
        source: parsed.source as VocSource,
        refId: parsed.refId,
        status,
        title: opts?.title ?? refKey
      });
    },
    [canWrite, patchMutation]
  );

  const value = useMemo<VocTriageContextValue>(
    () => ({
      ready: triageQuery.isSuccess,
      getStatus: (refKey: string) => statusMap.get(refKey) ?? "open",
      isDone: (refKey: string) => {
        const s = statusMap.get(refKey);
        return s === "done" || s === "dismissed";
      },
      toggleDone: (refKey: string, opts?: { title?: string }) => {
        const cur = statusMap.get(refKey) ?? "open";
        patchForKey(refKey, cur === "done" || cur === "dismissed" ? "open" : "done", opts);
      },
      setStatus: (refKey, status, opts) => patchForKey(refKey, status, opts)
    }),
    [triageQuery.isSuccess, statusMap, patchForKey]
  );

  return <VocTriageContext.Provider value={value}>{children}</VocTriageContext.Provider>;
}

export function useVocTriage(): VocTriageContextValue {
  const ctx = useContext(VocTriageContext);
  if (!ctx) throw new Error("useVocTriage must be used within VocTriageProvider");
  return ctx;
}

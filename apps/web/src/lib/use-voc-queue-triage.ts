"use client";

import { useCallback, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/contexts/auth-context";
import {
  patchVocTriage,
  type VocQueueItem,
  type VocQueueResponse,
  type VocTriageRow,
  type VocTriageStatus
} from "./voc-api";
import { isVocRefSessionClosed, markVocRefClosed, markVocRefOpen } from "./voc-session-closed";

export type VocTriageOverride = {
  status: VocTriageStatus;
  claimedByEmail: string | null;
};

function applyOverride(item: VocQueueItem, override?: VocTriageOverride): VocQueueItem {
  if (override) {
    return { ...item, status: override.status, claimedByEmail: override.claimedByEmail };
  }
  if (isVocRefSessionClosed(item.refKey)) {
    return { ...item, status: "done" };
  }
  return item;
}

export function useVocQueueTriage() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canWrite = user?.role !== "viewer";
  const [overrides, setOverrides] = useState<Record<string, VocTriageOverride>>({});
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const mergeItems = useCallback(
    (items: VocQueueItem[]) => items.map((item) => applyOverride(item, overrides[item.refKey])),
    [overrides]
  );

  const mutation = useMutation({
    mutationFn: patchVocTriage,
    onMutate: async (vars) => {
      setError(null);
      setPendingKey(vars.refKey);

      const optimistic: VocTriageOverride = {
        status: vars.status,
        claimedByEmail:
          vars.status === "claimed" ? (user?.email ?? "вы") : vars.status === "open" ? null : null
      };

      if (vars.status === "done" || vars.status === "dismissed") markVocRefClosed(vars.refKey);
      else markVocRefOpen(vars.refKey);

      setOverrides((prev) => ({ ...prev, [vars.refKey]: optimistic }));

      await queryClient.cancelQueries({ queryKey: ["voc", "queue"] });
      await queryClient.cancelQueries({ queryKey: ["voc", "triage"] });
      const snapshots = queryClient.getQueriesData<VocQueueResponse>({ queryKey: ["voc", "queue"] });
      const triageSnapshots = queryClient.getQueriesData<VocTriageRow[]>({ queryKey: ["voc", "triage"] });

      for (const [key, data] of snapshots) {
        if (!data) continue;
        queryClient.setQueryData(key, {
          ...data,
          items: data.items.map((item) =>
            item.refKey === vars.refKey ? { ...item, ...optimistic } : item
          )
        });
      }

      const triageRow: VocTriageRow = {
        refKey: vars.refKey,
        status: vars.status,
        claimedByEmail: optimistic.claimedByEmail,
        updatedAt: new Date().toISOString()
      };
      for (const [key, rows] of triageSnapshots) {
        if (!rows) continue;
        const idx = rows.findIndex((row) => row.refKey === vars.refKey);
        const next = idx >= 0 ? rows.map((row, i) => (i === idx ? { ...row, ...triageRow } : row)) : [...rows, triageRow];
        queryClient.setQueryData(key, next);
      }

      return { snapshots, triageSnapshots };
    },
    onError: (err, vars, ctx) => {
      if (vars.status === "done" || vars.status === "dismissed") markVocRefOpen(vars.refKey);
      setOverrides((prev) => {
        const next = { ...prev };
        delete next[vars.refKey];
        return next;
      });
      if (ctx?.snapshots) {
        for (const [key, data] of ctx.snapshots) {
          queryClient.setQueryData(key, data);
        }
      }
      if (ctx?.triageSnapshots) {
        for (const [key, data] of ctx.triageSnapshots) {
          queryClient.setQueryData(key, data);
        }
      }
      setError(err instanceof Error ? err.message : "Ошибка triage");
    },
    onSettled: (_data, err, vars) => {
      setPendingKey(null);
      void queryClient.invalidateQueries({ queryKey: ["voc", "triage"] });
      if (err || !vars) {
        void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
        return;
      }
      // Готово/снято: не дёргать очередь сразу — live-poll и кап слота возвращали карточку в «Сейчас».
      if (vars.status === "done" || vars.status === "dismissed") return;
      void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
      if (vars.status === "open" || vars.status === "claimed") {
        setOverrides((prev) => {
          const next = { ...prev };
          delete next[vars.refKey];
          return next;
        });
      }
    }
  });

  const setStatus = useCallback(
    (item: VocQueueItem, status: VocTriageStatus) => {
      if (!canWrite) {
        setError("Роль viewer доступна только для чтения");
        return;
      }
      mutation.mutate({
        refKey: item.refKey,
        source: item.source,
        refId: item.refId,
        status,
        title: item.title,
        vocScore: item.vocScore,
        vocPriority: item.vocPriority,
        vocReasons: item.vocReasons,
        meta: item.payload
      });
    },
    [canWrite, mutation]
  );

  return {
    userEmail: user?.email ?? null,
    mergeItems,
    setStatus,
    pendingKey,
    error,
    clearError: () => setError(null),
    isPending: mutation.isPending
  };
}

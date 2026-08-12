"use client";

import { useCallback, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/contexts/auth-context";
import {
  patchVocTriage,
  type VocQueueItem,
  type VocQueueResponse,
  type VocTriageStatus
} from "./voc-api";

export type VocTriageOverride = {
  status: VocTriageStatus;
  claimedByEmail: string | null;
};

function applyOverride(item: VocQueueItem, override?: VocTriageOverride): VocQueueItem {
  if (!override) return item;
  return { ...item, status: override.status, claimedByEmail: override.claimedByEmail };
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

      setOverrides((prev) => ({ ...prev, [vars.refKey]: optimistic }));

      await queryClient.cancelQueries({ queryKey: ["voc", "queue"] });
      const snapshots = queryClient.getQueriesData<VocQueueResponse>({ queryKey: ["voc", "queue"] });

      for (const [key, data] of snapshots) {
        if (!data) continue;
        queryClient.setQueryData(key, {
          ...data,
          items: data.items.map((item) =>
            item.refKey === vars.refKey ? { ...item, ...optimistic } : item
          )
        });
      }

      return { snapshots };
    },
    onError: (err, vars, ctx) => {
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
      setError(err instanceof Error ? err.message : "Ошибка triage");
    },
    onSuccess: (_data, vars) => {
      setOverrides((prev) => {
        const next = { ...prev };
        delete next[vars.refKey];
        return next;
      });
    },
    onSettled: () => {
      setPendingKey(null);
      void queryClient.invalidateQueries({ queryKey: ["voc", "queue"] });
      void queryClient.invalidateQueries({ queryKey: ["voc", "triage"] });
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

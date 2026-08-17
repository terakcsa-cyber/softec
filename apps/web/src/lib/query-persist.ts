import { dehydrate, hydrate, type DehydratedState, type QueryClient } from "@tanstack/react-query";

const STORAGE_KEY = "vip:query-cache:v1";
const MAX_AGE_MS = 30 * 60 * 1000;
const MAX_BYTES = 1_500_000;

const BLOCKED_ROOTS = new Set([
  "auth",
  "health",
  "settings",
  "ops",
  "queue",
  "readiness",
  "reconciliation",
  "updates",
  "tls"
]);

type PersistEnvelope = {
  savedAt: number;
  state: DehydratedState;
};

function storage(): Storage | null {
  if (typeof sessionStorage === "undefined") return null;
  return sessionStorage;
}

function rootKey(queryKey: readonly unknown[]): string {
  const first = queryKey[0];
  return typeof first === "string" ? first : "";
}

export function clearPersistedQueryCache(): void {
  try {
    storage()?.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}

export function restorePersistedQueries(client: QueryClient): void {
  const raw = (() => {
    try {
      return storage()?.getItem(STORAGE_KEY) ?? null;
    } catch {
      return null;
    }
  })();
  if (!raw) return;
  try {
    const env = JSON.parse(raw) as PersistEnvelope;
    if (!env?.savedAt || Date.now() - env.savedAt > MAX_AGE_MS) {
      clearPersistedQueryCache();
      return;
    }
    hydrate(client, env.state);
  } catch {
    clearPersistedQueryCache();
  }
}

export function persistQueryClientNow(client: QueryClient): void {
  try {
    const state = dehydrate(client, {
      shouldDehydrateQuery: (q) => {
        if (q.state.status !== "success") return false;
        const root = rootKey(q.queryKey);
        if (!root || BLOCKED_ROOTS.has(root)) return false;
        return true;
      }
    });
    const payload = JSON.stringify({ savedAt: Date.now(), state } satisfies PersistEnvelope);
    if (payload.length > MAX_BYTES) return;
    storage()?.setItem(STORAGE_KEY, payload);
  } catch {
    // quota / private mode
  }
}

export function subscribeQueryPersist(client: QueryClient): () => void {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const schedule = () => {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      persistQueryClientNow(client);
    }, 800);
  };
  persistQueryClientNow(client);
  const unsub = client.getQueryCache().subscribe(schedule);
  return () => {
    unsub();
    if (timer) clearTimeout(timer);
    persistQueryClientNow(client);
  };
}

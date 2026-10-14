"use client";

import { useEffect, useState } from "react";

export type VcNotice = {
  id: string;
  kind: "news" | "cve";
  source: string;
  title: string;
  body?: string;
  href: string;
  at: string;
  read: boolean;
};

const STORAGE_KEY = "vip:vc-notices";
const SEEDED_KEY = "vip:vc-notices:seeded";
const MAX_ITEMS = 40;

type State = { items: VcNotice[]; ready: boolean };

let state: State = { items: [], ready: false };
let hydrated = false;
const listeners = new Set<() => void>();

function emit() {
  for (const listener of listeners) listener();
}

function readStorage(): VcNotice[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as VcNotice[];
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item) => item && typeof item.id === "string" && typeof item.title === "string");
  } catch {
    return [];
  }
}

function writeStorage(items: VcNotice[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
  } catch {
    // ignore quota
  }
}

function hydrate() {
  if (hydrated || typeof window === "undefined") return;
  hydrated = true;
  state = { ...state, items: readStorage() };
}

export function noticesSeeded() {
  try {
    return localStorage.getItem(SEEDED_KEY) === "1";
  } catch {
    return false;
  }
}

export function markNoticesSeeded() {
  try {
    localStorage.setItem(SEEDED_KEY, "1");
  } catch {
    // ignore
  }
}

export function markNoticesReady() {
  if (state.ready) return;
  state = { ...state, ready: true };
  emit();
}

/** Убрать старые всплытия ФСТЭК из колокольчика — лента живёт только в модуле ФСТЭК. */
export function dropFstecNotices() {
  hydrate();
  const items = state.items.filter((item) => item.source !== "ФСТЭК" && !item.id.startsWith("fstec:"));
  if (items.length === state.items.length) return;
  state = { ...state, items };
  writeStorage(items);
  emit();
}

export function ingestNotices(incoming: Array<Omit<VcNotice, "read">>, mode: "seed" | "live") {
  hydrate();
  const merged = new Map(state.items.map((item) => [item.id, item]));
  const fresh: Array<Omit<VcNotice, "read">> = [];
  let changed = false;
  for (const item of incoming) {
    if (!item.id || !item.title) continue;
    const prev = merged.get(item.id);
    if (!prev) {
      fresh.push(item);
      merged.set(item.id, { ...item, read: mode === "seed" });
      changed = true;
      continue;
    }
    if (prev.title !== item.title || prev.body !== item.body || prev.href !== item.href || prev.at !== item.at || prev.source !== item.source) {
      merged.set(item.id, { ...prev, title: item.title, body: item.body, href: item.href, at: item.at, source: item.source, kind: item.kind });
      changed = true;
    }
  }
  if (!changed) return [];
  const items = [...merged.values()].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, MAX_ITEMS);
  state = { ...state, items };
  writeStorage(items);
  emit();
  return fresh;
}

export function markNoticesRead() {
  hydrate();
  if (!state.items.some((item) => !item.read)) return;
  const items = state.items.map((item) => (item.read ? item : { ...item, read: true }));
  state = { ...state, items };
  writeStorage(items);
  emit();
}

export function useVcNotices() {
  const [snapshot, setSnapshot] = useState<State>({ items: [], ready: false });
  useEffect(() => {
    hydrate();
    setSnapshot(state);
    const listener = () => setSnapshot(state);
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);
  return snapshot;
}

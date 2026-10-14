import { useSyncExternalStore } from "react";
import type { Severity, Vulnerability, VulnStatus } from "./types";

export type VulnMutation = {
  status?: VulnStatus;
  taskId?: string;
  assignee?: string;
  priority?: Severity;
};

let mutations: Record<string, VulnMutation> = {};
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((listener) => listener());
}

export function getMutations() {
  return mutations;
}

export function subscribeMutations(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useVcMutations() {
  return useSyncExternalStore(subscribeMutations, getMutations, getMutations);
}

export function mutateVulns(ids: string[], patch: VulnMutation) {
  const next = { ...mutations };
  ids.forEach((id) => {
    next[id] = { ...next[id], ...patch };
  });
  mutations = next;
  emit();
}

export function applyMutation(vuln: Vulnerability): Vulnerability {
  const patch = mutations[vuln.id];
  if (!patch) return vuln;
  return {
    ...vuln,
    status: patch.status ?? vuln.status,
    taskId: patch.taskId ?? vuln.taskId
  };
}

export function nextTaskId() {
  return `VM-${13000 + Math.floor(Math.random() * 8000)}`;
}

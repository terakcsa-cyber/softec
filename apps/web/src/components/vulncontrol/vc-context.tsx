"use client";

import type { Route } from "next";

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { isSettingsSection, type SettingsSectionId } from "@/components/dashboard/settings-nav";
import { EMPTY_QUERY, type VcQuery } from "@/lib/vulncontrol/types";

const HANDOFF_KEY = "vip:vc-handoff";
const TASK_KEY = "vip:vc-task";
const CATALOG_KEY = "vip:vc-catalog";
const SETTINGS_KEY = "vip:vc-settings-section";
const TASK_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function vulnerabilityPath(cveId: string, taskId?: string | null): Route {
  const path = `/vulnerabilities/${encodeURIComponent(cveId)}`;
  if (!taskId || !TASK_ID.test(taskId)) return path as Route;
  return `${path}?task=${encodeURIComponent(taskId)}` as Route;
}

export function rememberTask(taskId: string) {
  if (!TASK_ID.test(taskId)) return;
  sessionStorage.setItem(TASK_KEY, taskId);
}

export function parseTaskId(value: string | null) {
  if (!value || !TASK_ID.test(value)) return null;
  return value;
}

export function taskFromLocation() {
  if (typeof window === "undefined") return null;
  return parseTaskId(new URLSearchParams(window.location.search).get("task"));
}

export function stashVcPage(page: VcPage, favorite?: string) {
  sessionStorage.setItem(HANDOFF_KEY, favorite ? `${page}:${favorite}` : page);
}

export function stashCatalogFilter(filter: { vendor: string; product: string; q?: string }) {
  const vendor = filter.vendor.trim() || "all";
  const product = filter.product.trim() || "all";
  const q = filter.q?.trim() || "";
  sessionStorage.setItem(CATALOG_KEY, JSON.stringify({ vendor, product, q }));
}

export type VcPage = "dashboard" | "vulns" | "bdu" | "products" | "tasks" | "patches" | "analytics" | "reports" | "integrations" | "settings";

type Favorite = "critical" | "kev" | "epss" | "nopatch" | "overdue";

type Ctx = {
  page: VcPage;
  setPage: (page: VcPage) => void;
  query: VcQuery;
  setQuery: (patch: Partial<VcQuery>) => void;
  resetQuery: () => void;
  applyFavorite: (favorite: Favorite) => void;
  selectedId: string | null;
  setSelectedId: (id: string | null) => void;
  focusTaskId: string | null;
  openTask: (taskId: string) => void;
  collapsed: boolean;
  setCollapsed: (value: boolean) => void;
  picked: Record<string, boolean>;
  setPicked: (value: Record<string, boolean> | ((current: Record<string, boolean>) => Record<string, boolean>)) => void;
  notice: string | null;
  flash: (text: string) => void;
  settingsSection: SettingsSectionId;
  setSettingsSection: (section: SettingsSectionId) => void;
};

const VcContext = createContext<Ctx | null>(null);

function readCveParam(value: string | null) {
  if (!value || !/^CVE-\d{4}-\d{4,}$/i.test(value)) return null;
  return value.toUpperCase();
}

export function VcProvider({ children, initialPage = "dashboard" }: { children: ReactNode; initialPage?: VcPage }) {
  const [page, setPage] = useState<VcPage>(initialPage);
  const [query, setQueryState] = useState<VcQuery>(EMPTY_QUERY);
  const [selectedId, setSelectedIdState] = useState<string | null>(null);
  const [focusTaskId, setFocusTaskId] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [notice, setNotice] = useState<string | null>(null);
  const [settingsSection, setSettingsSectionState] = useState<SettingsSectionId>("appearance");

  useEffect(() => {
    const onCveCard = /^\/vulnerabilities\/[^/]+/.test(window.location.pathname);
    const stored = sessionStorage.getItem(HANDOFF_KEY);
    if (stored && !onCveCard) {
      sessionStorage.removeItem(HANDOFF_KEY);
      const [pageName, favorite] = stored.split(":");
      const allowed: VcPage[] = ["dashboard", "vulns", "bdu", "products", "tasks", "patches", "analytics", "reports", "integrations", "settings"];
      if (allowed.includes(pageName as VcPage)) setPage(pageName as VcPage);
      if (favorite === "critical") setQueryState({ ...EMPTY_QUERY, severity: "critical" });
      if (favorite === "kev") setQueryState({ ...EMPTY_QUERY, tab: "kev" });
      if (favorite === "epss") setQueryState({ ...EMPTY_QUERY, tab: "epss" });
      if (favorite === "overdue") setQueryState({ ...EMPTY_QUERY, tab: "overdue" });
    }
    const sectionRaw = sessionStorage.getItem(SETTINGS_KEY);
    if (isSettingsSection(sectionRaw)) setSettingsSectionState(sectionRaw);
    const catalogRaw = sessionStorage.getItem(CATALOG_KEY);
    if (catalogRaw) {
      sessionStorage.removeItem(CATALOG_KEY);
      try {
        const parsed = JSON.parse(catalogRaw) as { vendor?: unknown; product?: unknown; q?: unknown };
        const vendor = typeof parsed.vendor === "string" && parsed.vendor.trim() ? parsed.vendor.trim() : "all";
        const product = typeof parsed.product === "string" && parsed.product.trim() ? parsed.product.trim() : "all";
        const q = typeof parsed.q === "string" ? parsed.q.trim() : "";
        setQueryState((current) => ({
          ...current,
          q,
          tab: "all",
          severity: "all",
          status: "all",
          vendor,
          product
        }));
        setPage("vulns");
      } catch {
        /* ignore broken handoff */
      }
    }
    const focus = sessionStorage.getItem(TASK_KEY);
    if (focus) {
      sessionStorage.removeItem("vip:vc-task");
      setFocusTaskId(focus);
      setPage("tasks");
    }
    const selected = readCveParam(new URLSearchParams(window.location.search).get("selected"));
    if (selected) {
      setSelectedIdState(selected);
      setPage("vulns");
    }
  }, []);

  const setSelectedId = (id: string | null) => {
    setSelectedIdState(id);
    if (window.location.pathname.startsWith("/vulnerabilities/")) return;
    const url = new URL(window.location.href);
    if (id) url.searchParams.set("selected", id);
    else url.searchParams.delete("selected");
    const next = `${url.pathname}${url.search}`;
    if (`${window.location.pathname}${window.location.search}` !== next) window.history.replaceState(null, "", next);
  };

  const value = useMemo<Ctx>(() => ({
    page,
    setPage,
    query,
    setQuery: (patch) => setQueryState((current) => ({ ...current, ...patch })),
    resetQuery: () => setQueryState(EMPTY_QUERY),
    applyFavorite: (favorite) => {
      const next: VcQuery = { ...EMPTY_QUERY };
      if (favorite === "critical") {
        next.severity = "critical";
        setQueryState(next);
        setPage("vulns");
        return;
      }
      if (favorite === "kev") {
        next.tab = "kev";
        setQueryState(next);
        setPage("vulns");
        return;
      }
      if (favorite === "epss") {
        next.tab = "epss";
        setQueryState(next);
        setPage("vulns");
        return;
      }
      if (favorite === "nopatch") {
        setQueryState(EMPTY_QUERY);
        setPage("patches");
        return;
      }
      next.tab = "overdue";
      setQueryState(next);
      setPage("tasks");
    },
    selectedId,
    setSelectedId,
    focusTaskId,
    openTask: (taskId) => {
      setFocusTaskId(taskId);
      setPage("tasks");
    },
    collapsed,
    setCollapsed,
    picked,
    setPicked,
    notice,
    flash: (text) => {
      setNotice(text);
      window.setTimeout(() => setNotice((current) => (current === text ? null : current)), 2400);
    },
    settingsSection,
    setSettingsSection: (id) => {
      setSettingsSectionState(id);
      try {
        sessionStorage.setItem(SETTINGS_KEY, id);
      } catch {
        /* ignore */
      }
    }
  }), [collapsed, focusTaskId, notice, page, picked, query, selectedId, settingsSection]);

  return <VcContext.Provider value={value}>{children}</VcContext.Provider>;
}

export function useVc() {
  const ctx = useContext(VcContext);
  if (!ctx) throw new Error("useVc outside provider");
  return ctx;
}

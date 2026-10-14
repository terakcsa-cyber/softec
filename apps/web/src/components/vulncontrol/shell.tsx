"use client";

import { useEffect, useRef, useState, type RefObject } from "react";
import type { Route } from "next";
import { usePathname, useRouter } from "next/navigation";
import {
  Bell,
  Bug,
  Calendar,
  ChevronDown,
  ClipboardList,
  BarChart3,
  BookMarked,
  FileText,
  LayoutDashboard,
  Moon,
  Package,
  Plug,
  Settings,
  Shield,
  Sun,
  Wrench
} from "lucide-react";
import type { SettingsSectionId } from "@/components/dashboard/settings-nav";
import { cn } from "@/components/ui/cn";
import { useAuth } from "@/contexts/auth-context";
import { useTheme } from "@/contexts/theme-context";
import { markNoticesRead, useVcNotices, type VcNotice } from "@/lib/vc-notices";
import { rememberTask, stashVcPage, taskFromLocation, type VcPage } from "./vc-context";
import { useVc } from "./vc-context";
import { SearchSuggest } from "./search-suggest";
import { SettingsSectionList } from "./settings-menu";
import { VcDrop, useAnchoredStyle, vcMenuItem } from "./vc-pop";

const NAV: Array<{ id: VcPage; label: string; icon: typeof LayoutDashboard }> = [
  { id: "dashboard", label: "Дашборд", icon: LayoutDashboard },
  { id: "vulns", label: "Уязвимости", icon: Bug },
  { id: "bdu", label: "БДУ", icon: BookMarked },
  { id: "products", label: "Продукты", icon: Package },
  { id: "tasks", label: "Задачи", icon: ClipboardList },
  { id: "patches", label: "Патчи", icon: Wrench },
  { id: "analytics", label: "Аналитика", icon: BarChart3 },
  { id: "reports", label: "Отчёты", icon: FileText },
  { id: "integrations", label: "Интеграции", icon: Plug },
  { id: "settings", label: "Настройки", icon: Settings }
];

const FAVORITES = [
  { id: "critical" as const, label: "Критические уязвимости" },
  { id: "kev" as const, label: "KEV / Exploited" },
  { id: "epss" as const, label: "Высокий EPSS (>0.7)" },
  { id: "nopatch" as const, label: "Нет исправления" },
  { id: "overdue" as const, label: "Просроченные задачи" }
];

const RANGES = [
  ["7d", "Последние 7 дней"],
  ["30d", "Последние 30 дней"],
  ["90d", "Последние 90 дней"],
  ["all", "Всё время"]
] as const;

function roleLabel(role: string | undefined) {
  if (role === "admin") return "Администратор";
  if (role === "analyst") return "Аналитик";
  if (role === "viewer") return "Наблюдатель";
  return role ?? "";
}

function initials(email: string) {
  const local = email.split("@")[0] ?? "";
  const parts = local.split(/[.\-_]/).filter(Boolean);
  const raw = parts.length >= 2 ? `${parts[0]![0] ?? ""}${parts[1]![0] ?? ""}` : local.slice(0, 2);
  return raw.toUpperCase() || "—";
}

export function VcShell({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const { page, setPage, query, setQuery, applyFavorite, collapsed, setCollapsed, settingsSection, setSettingsSection } = useVc();
  const go = (next: VcPage) => {
    const onList = pathname === "/vulnerabilities";
    if (next === "vulns" && !onList) {
      router.push("/vulnerabilities");
      return;
    }
    if (next !== "vulns" && pathname !== "/") {
      if (next === "tasks") {
        const taskId = taskFromLocation();
        if (taskId) rememberTask(taskId);
      }
      stashVcPage(next);
      router.push("/");
      return;
    }
    setPage(next);
  };
  const openSettingsSection = (id: SettingsSectionId) => {
    setSettingsSection(id);
    go("settings");
  };
  const { theme, setTheme } = useTheme();
  const [notes, setNotes] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const notesRef = useRef<HTMLDivElement>(null);
  const settingsRef = useRef<HTMLDivElement>(null);
  const settingsListRef = useRef<HTMLDivElement>(null);
  const rangeRef = useRef<HTMLDivElement>(null);
  const inbox = useVcNotices();
  const unread = inbox.items.filter((item) => !item.read).length;
  const [rangeOpen, setRangeOpen] = useState(false);
  const rangeLabel = RANGES.find((item) => item[0] === query.range)?.[1] ?? "Последние 30 дней";

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        document.getElementById("vc-search")?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!notes) return;
    const onDoc = (event: PointerEvent) => {
      if (!notesRef.current?.contains(event.target as Node)) {
        markNoticesRead();
        setNotes(false);
      }
    };
    document.addEventListener("pointerdown", onDoc);
    return () => document.removeEventListener("pointerdown", onDoc);
  }, [notes]);

  useEffect(() => {
    if (!settingsOpen) return;
    const onDoc = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (settingsRef.current?.contains(target)) return;
      if (target instanceof Element && target.closest("#vc-settings-menu")) return;
      setSettingsOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSettingsOpen(false);
    };
    document.addEventListener("pointerdown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [settingsOpen]);

  useEffect(() => {
    if (!settingsOpen || collapsed) return;
    settingsListRef.current?.scrollIntoView({ block: "nearest" });
  }, [settingsOpen, collapsed]);

  return (
    <div
      className="vc-shell flex h-full min-h-0 text-[13px] text-[var(--vc-text)]"
      style={{ background: "var(--vc-bg)" }}
    >
      <aside className={cn("relative z-20 flex h-full min-h-0 shrink-0 flex-col border-r border-[var(--vc-border)] bg-[var(--vc-sidebar)]", collapsed ? "w-[72px]" : "w-[235px]")}>
        <button type="button" onClick={() => setCollapsed(!collapsed)} className="flex items-center gap-2.5 px-3 py-3 text-left">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[#2f6bff] text-white shadow-[0_0_18px_rgba(47,107,255,0.45)]">
            <Shield className="h-4 w-4" />
          </span>
          {collapsed ? null : (
            <span className="min-w-0">
              <span className="block text-[14px] font-semibold leading-none">VulnControl</span>
              <span className="mt-1 block text-[10px] leading-tight text-[var(--vc-muted)]">Vulnerability Management Platform</span>
            </span>
          )}
        </button>
        <nav className={cn("mt-1 min-h-0 space-y-0.5 px-2", collapsed ? "overflow-visible" : "vc-pop flex-1 overflow-y-auto")}>
          {NAV.map((item) => {
            const Icon = item.icon;
            const active = page === item.id;
            if (item.id === "settings") {
              return (
                <div key={item.id} ref={settingsRef} className="relative">
                  <button
                    type="button"
                    id="vc-settings-nav"
                    title={item.label}
                    aria-expanded={settingsOpen}
                    aria-controls="vc-settings-menu"
                    onClick={() => setSettingsOpen((value) => !value)}
                    className={cn(
                      "flex h-9 w-full items-center gap-2.5 rounded-lg px-2.5 text-[13px] transition",
                      active
                        ? "bg-[#2f6bff] text-white shadow-[0_0_16px_rgba(47,107,255,0.35)]"
                        : settingsOpen
                          ? "bg-[var(--vc-hover)] text-[var(--vc-text)]"
                          : "text-[var(--vc-nav)] hover:bg-[var(--vc-hover)]"
                    )}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    {collapsed ? null : (
                      <>
                        <span className="truncate">{item.label}</span>
                        <ChevronDown className={cn("ml-auto h-3.5 w-3.5 shrink-0 transition-transform duration-200", settingsOpen && "rotate-180")} />
                      </>
                    )}
                  </button>
                  {settingsOpen && !collapsed ? (
                    <div id="vc-settings-menu" ref={settingsListRef} className="vc-unfold mb-1 ml-[18px] mt-0.5 border-l border-[var(--vc-border)] pl-1.5">
                      <SettingsSectionList
                        active={page === "settings" ? settingsSection : null}
                        onPick={openSettingsSection}
                        labelledBy="vc-settings-nav"
                      />
                    </div>
                  ) : null}
                  {settingsOpen && collapsed ? (
                    <VcDrop
                      open
                      portal
                      anchorRef={settingsRef}
                      onClose={() => setSettingsOpen(false)}
                      align="after"
                      width={220}
                      maxHeight={420}
                      className="vc-unfold p-1"
                    >
                      <div id="vc-settings-menu">
                        <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Настройки</div>
                        <SettingsSectionList
                          active={page === "settings" ? settingsSection : null}
                          onPick={openSettingsSection}
                          labelledBy="vc-settings-nav"
                        />
                      </div>
                    </VcDrop>
                  ) : null}
                </div>
              );
            }
            return (
              <button
                key={item.id}
                type="button"
                title={item.label}
                onClick={() => {
                  setSettingsOpen(false);
                  go(item.id);
                }}
                className={cn(
                  "flex h-9 w-full items-center gap-2.5 rounded-lg px-2.5 text-[13px] transition",
                  active ? "bg-[#2f6bff] text-white shadow-[0_0_16px_rgba(47,107,255,0.35)]" : "text-[var(--vc-nav)] hover:bg-[var(--vc-hover)]"
                )}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {collapsed ? null : <span className="truncate">{item.label}</span>}
              </button>
            );
          })}
        </nav>
        {collapsed ? null : (
          <div className="mt-auto px-3 pb-3">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-[var(--vc-muted)]">Избранное</div>
            <div className="space-y-0.5">
              {FAVORITES.map((item) => (
                <button key={item.id} type="button" onClick={() => {
                  if (pathname.startsWith("/vulnerabilities/")) {
                    const dest = item.id === "nopatch" ? "patches" : item.id === "overdue" ? "tasks" : "vulns";
                    stashVcPage(dest, item.id);
                    router.push(dest === "vulns" ? "/vulnerabilities" : "/");
                    return;
                  }
                  applyFavorite(item.id);
                }} className="block w-full truncate rounded-md px-2 py-1.5 text-left text-[12px] text-[var(--vc-nav)] hover:bg-[var(--vc-hover)]">
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        )}
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="relative z-30 flex h-14 shrink-0 items-center gap-3 border-b border-[var(--vc-border)] bg-[var(--vc-header)] px-4">
          <SearchSuggest />
          <div ref={rangeRef}>
            <button type="button" onClick={() => setRangeOpen((value) => !value)} className="inline-flex h-9 items-center gap-1.5 whitespace-nowrap rounded-lg border border-[var(--vc-border)] px-2.5 text-[12px] leading-none">
              <Calendar className="h-3.5 w-3.5 text-[var(--vc-muted)]" />
              {rangeLabel}
            </button>
            <VcDrop open={rangeOpen} anchorRef={rangeRef} onClose={() => setRangeOpen(false)} align="end" width={192} maxHeight={240} className="p-1">
              {RANGES.map(([id, label]) => (
                <button key={id} type="button" className={vcMenuItem} onClick={() => { setQuery({ range: id }); setRangeOpen(false); }}>
                  {label}
                </button>
              ))}
            </VcDrop>
          </div>
          <div className="relative" ref={notesRef}>
            <button
              type="button"
              onClick={() => setNotes((value) => {
                if (value) markNoticesRead();
                return !value;
              })}
              className="relative inline-flex h-9 w-9 items-center justify-center rounded-lg border border-[var(--vc-border)]"
              aria-label={unread > 0 ? `Уведомления, ${unread} ${unread % 10 === 1 && unread % 100 !== 11 ? "новое" : "новых"}` : "Уведомления"}
            >
              <Bell className="h-4 w-4" />
              {unread > 0 ? (
                <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-[var(--vc-critical)] px-1 text-[10px] font-semibold leading-none text-white">
                  {unread > 9 ? "9+" : unread}
                </span>
              ) : null}
            </button>
            {notes ? <NoticePanel anchorRef={notesRef} items={inbox.items} ready={inbox.ready} onOpen={(item) => {
              markNoticesRead();
              setNotes(false);
              if (item.href.startsWith("/")) router.push(item.href as Route);
              else window.open(item.href, "_blank", "noopener,noreferrer");
            }} /> : null}
          </div>
          <button type="button" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-[var(--vc-border)]" title="Тема">
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <div className="flex items-center gap-2">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-[#1d4ed8] text-[11px] font-semibold text-white">{initials(user?.email ?? "")}</span>
            <span className="hidden max-w-[180px] leading-tight lg:block">
              <span className="block truncate text-[12px] font-medium">{user?.email ?? "—"}</span>
              <span className="block truncate text-[10px] text-[var(--vc-muted)]">{roleLabel(user?.role)}</span>
            </span>
          </div>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto bg-[var(--vc-bg)] px-3 py-3">{children}</div>
      </div>
    </div>
  );
}

function formatNoticeTime(iso: string) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("ru-RU", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(date);
}

function NoticePanel({ anchorRef, items, ready, onOpen }: { anchorRef: RefObject<HTMLDivElement | null>; items: VcNotice[]; ready: boolean; onOpen: (item: VcNotice) => void }) {
  const menuRef = useRef<HTMLDivElement>(null);
  const style = useAnchoredStyle(true, anchorRef, menuRef, "end", 380, 480, String(items.length));
  return (
    <div ref={menuRef} className="vc-pop flex min-h-0 flex-col overflow-hidden rounded-lg border border-[var(--vc-border)] bg-[var(--vc-surface)] shadow-xl" style={style}>
      <div className="flex shrink-0 items-center justify-between border-b border-[var(--vc-border)] px-3 py-2">
        <span className="text-[12px] font-medium">Уведомления</span>
        <span className="text-[10px] text-[var(--vc-muted)]">{items.length ? `${items.length}` : ""}</span>
      </div>
      {items.length === 0 ? (
        <div className="px-3 py-4 text-[12px] text-[var(--vc-muted)]">{ready ? "Пока нет событий" : "Собираю ленту…"}</div>
      ) : (
        <ul className="vc-pop min-h-0 flex-1 overflow-y-auto">
          {items.map((item) => (
            <li key={item.id}>
              <button type="button" onClick={() => onOpen(item)} className="flex w-full min-w-0 gap-2 px-3 py-2 text-left leading-snug hover:bg-[var(--vc-hover)]">
                <span className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", item.read ? "bg-transparent" : "bg-[#2f6bff]")} />
                <span className="min-w-0 flex-1">
                  <span className="flex items-center justify-between gap-2">
                    <span className="truncate text-[10px] uppercase tracking-wide text-[var(--vc-muted)]">{item.source}</span>
                    <span className="shrink-0 text-[10px] text-[var(--vc-muted)]">{formatNoticeTime(item.at)}</span>
                  </span>
                  <span className="mt-0.5 block truncate text-[12px] font-medium">{item.title}</span>
                  {item.body ? <span className="mt-0.5 line-clamp-2 block text-[11px] leading-snug text-[var(--vc-muted)]">{item.body}</span> : null}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

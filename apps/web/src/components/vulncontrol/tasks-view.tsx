"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/contexts/auth-context";
import { taskIssueKey } from "../dashboard/vuln-task-ui";
import { useVc, vulnerabilityPath } from "./vc-context";
import {
  cvssBand,
  formatDate,
  isOverdue,
  taskStatusLabel,
  useCveDetail,
  useTaskDetail,
  useVulnTasks,
  type LiveTask,
  type TaskDetail,
  type TaskEvent
} from "@/lib/vulncontrol/live";
import { tint } from "@/lib/vulncontrol/risk";
import { buildVulnCard, formatEpss, patchTask, type VulnCard } from "@/lib/vulncontrol/vuln-model";

const FILTERS = [
  { id: "all", label: "Все задачи" },
  { id: "mine", label: "Мои задачи" },
  { id: "critical", label: "Критические" },
  { id: "unassigned", label: "Без исполнителя" },
  { id: "overdue", label: "Просроченные" },
  { id: "kev", label: "KEV / Exploited" }
] as const;

type FilterId = (typeof FILTERS)[number]["id"];

const TRACK = [
  { key: "new", label: "Новая" },
  { key: "in_progress", label: "В работе" },
  { key: "closed", label: "Закрыта" }
];

const STATUS_COLOR: Record<string, string> = {
  new: "var(--vc-slate)",
  in_progress: "var(--vc-primary)",
  closed: "var(--vc-success)"
};

export function TasksView() {
  const { query, focusTaskId } = useVc();
  const { user } = useAuth();
  const tasks = useVulnTasks(query.q);
  const [filter, setFilter] = useState<FilterId>(query.tab === "overdue" ? "overdue" : "all");
  const [picked, setPicked] = useState<string | null>(focusTaskId);
  useEffect(() => {
    if (query.tab === "overdue") setFilter("overdue");
  }, [query.tab]);
  useEffect(() => {
    if (focusTaskId) setPicked(focusTaskId);
  }, [focusTaskId]);

  const items = tasks.data?.items ?? [];
  const email = user?.email ?? null;
  const filtered = useMemo(
    () => items.filter((task) => matchFilter(task, filter, email)),
    [items, filter, email]
  );
  const rows = useMemo(() => {
    if (!picked || filtered.some((task) => task.id === picked)) return filtered;
    const current = items.find((task) => task.id === picked);
    return current ? [current, ...filtered] : filtered;
  }, [filtered, items, picked]);
  const activeId = rows.some((task) => task.id === picked) ? picked : rows[0]?.id ?? null;

  function selectFilter(id: FilterId) {
    setFilter(id);
    setPicked((current) => {
      const next = items.filter((task) => matchFilter(task, id, email));
      if (current && next.some((task) => task.id === current)) return current;
      return next[0]?.id ?? null;
    });
  }

  return (
    <div className="grid items-start gap-3 xl:grid-cols-[240px_minmax(0,1fr)]">
      <aside className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)]">
        <div className="border-b border-[var(--vc-border)] px-3 py-2.5">
          <h1 className="text-[14px] font-semibold">Задачи</h1>
          <p className="text-[11px] text-[var(--vc-muted)]">{tasks.isLoading ? "Загрузка…" : `${rows.length} в срезе`}</p>
        </div>
        <div className="flex flex-col gap-0.5 p-2">
          {FILTERS.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => selectFilter(item.id)}
              className={`rounded-md px-2 py-1.5 text-left text-[12px] ${filter === item.id ? "bg-[var(--vc-primary)] text-white" : "text-[var(--vc-muted)] hover:bg-[var(--vc-hover)] hover:text-[var(--vc-text)]"}`}
            >
              {item.label}
            </button>
          ))}
        </div>
        <div className="vc-pop max-h-[640px] overflow-y-auto border-t border-[var(--vc-border)]">
          {rows.map((task) => {
            const on = task.id === activeId;
            const tone = STATUS_COLOR[task.status] ?? "var(--vc-slate)";
            return (
              <button
                key={task.id}
                type="button"
                onClick={() => setPicked(task.id)}
                className={`block w-full border-b border-[var(--vc-line)] px-3 py-2 text-left ${on ? "bg-[var(--vc-selected)] text-white" : "hover:bg-[var(--vc-hover-soft)]"}`}
              >
                <div className="flex items-center gap-2">
                  <span className={`font-mono text-[11px] font-semibold ${on ? "text-white" : "text-[var(--vc-link)]"}`}>{taskIssueKey(task.id)}</span>
                  <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold text-white" style={{ background: tone }}>{taskStatusLabel(task.status)}</span>
                </div>
                <div className="mt-1 line-clamp-2 text-[12px] font-medium leading-snug">{task.title}</div>
                <div className={`mt-0.5 truncate text-[11px] ${on ? "text-white/75" : "text-[var(--vc-muted)]"}`}>{task.product_display || task.vendor_display || "—"}</div>
              </button>
            );
          })}
          {!tasks.isLoading && !rows.length ? <p className="px-3 py-6 text-[12px] text-[var(--vc-muted)]">В этом срезе задач нет.</p> : null}
        </div>
      </aside>
      {activeId ? <TaskDesk taskId={activeId} email={user?.email ?? null} /> : <EmptyDesk loading={tasks.isLoading} />}
    </div>
  );
}

function EmptyDesk({ loading }: { loading: boolean }) {
  return (
    <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-4 py-8">
      <h2 className="text-[16px] font-semibold">Задачи</h2>
      <p className="mt-2 text-[12px] text-[var(--vc-muted)]">{loading ? "Загрузка реестра задач…" : "Задач пока нет. Карточка появится, когда в каталоге будет хотя бы одна."}</p>
    </section>
  );
}

function TaskDesk({ taskId, email }: { taskId: string; email: string | null }) {
  const router = useRouter();
  const client = useQueryClient();
  const detail = useTaskDetail(taskId);
  const task = detail.data?.task;
  const cves = detail.data?.cves ?? [];
  const events = detail.data?.events ?? [];
  const primary = [...cves].sort((a, b) => (b.risk_score ?? -1) - (a.risk_score ?? -1))[0] ?? null;
  const cveDetail = useCveDetail(primary?.cve_id ?? null);
  const card = primary ? buildVulnCard(primary.cve_id, cveDetail.data, []) : null;
  const [tab, setTab] = useState<"overview" | "remediation" | "vuln" | "activity" | "notes" | "history">("overview");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setTab("overview");
    setNotes(String(detail.data?.task.notes_md ?? ""));
    setError(null);
  }, [taskId, detail.data?.task.notes_md]);

  async function save(body: { owner?: string | null; status?: string; notesMd?: string; dueDate?: string | null }, label: string) {
    setBusy(label);
    setError(null);
    const detailKey = ["vc", "task", taskId] as const;
    await client.cancelQueries({ queryKey: detailKey });
    await client.cancelQueries({ queryKey: ["vc", "tasks"] });
    const previous = client.getQueryData<TaskDetail>(detailKey);
    const listSnapshots = client.getQueriesData<{ items: LiveTask[] }>({ queryKey: ["vc", "tasks"] });
    const touchesState = body.status !== undefined || body.owner !== undefined || body.dueDate !== undefined || body.notesMd !== undefined;
    if (touchesState) {
      const base = previous?.task ?? listSnapshots.flatMap(([, data]) => data?.items ?? []).find((item) => item.id === taskId);
      const next = base ? applyTaskPatch(base, body, email) : null;
      if (previous && next) {
        client.setQueryData<TaskDetail>(detailKey, {
          ...previous,
          task: {
            ...previous.task,
            status: next.status,
            owner: next.owner,
            due_date: next.due_date,
            notes_md: next.notes_md
          }
        });
      }
      if (next) {
        client.setQueriesData<{ items: LiveTask[] }>({ queryKey: ["vc", "tasks"] }, (current) => {
          if (!current?.items) return current;
          return {
            ...current,
            items: current.items.map((item) => item.id === taskId
              ? { ...item, status: next.status, owner: next.owner, due_date: next.due_date, notes_md: next.notes_md }
              : item)
          };
        });
      }
    }
    try {
      await patchTask(taskId, body);
      await client.invalidateQueries({ queryKey: ["vc", "task", taskId] });
      await client.invalidateQueries({ queryKey: ["vc", "tasks"] });
      await client.invalidateQueries({ queryKey: ["vc", "tasks-for"] });
    } catch (cause) {
      if (previous) client.setQueryData(detailKey, previous);
      for (const [key, data] of listSnapshots) client.setQueryData(key, data);
      setError(cause instanceof Error ? cause.message : "Не сохранилось");
    } finally {
      setBusy(null);
    }
  }

  function assignMe() {
    if (!email || !task) return;
    void save(task.status === "new" ? { owner: email, status: "in_progress" } : { owner: email }, "owner");
  }

  if (detail.isLoading || !task) {
    return <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-4 py-8 text-[12px] text-[var(--vc-muted)]">{detail.isError ? "Карточка задачи не загрузилась." : "Загрузка задачи…"}</section>;
  }

  const assignDisabled = !email || busy != null || (task.owner === email && task.status !== "new");
  const openCve = (cveId: string) => router.push(vulnerabilityPath(cveId, task.id));
  const key = taskIssueKey(task.id);
  const priority = priorityMeta(task.priority_local);
  const statusColor = STATUS_COLOR[task.status] ?? "var(--vc-slate)";
  const risk = task.score_final ?? primary?.risk_score ?? null;
  const cvss = primary?.cvss_base ?? card?.cvss ?? null;
  const epss = primary?.epss ?? card?.epss ?? null;
  const kev = Boolean(primary?.exploit_known || (task.stats?.kevCount ?? 0) > 0 || card?.kev);
  const band = cvssBand(cvss);
  const step = TRACK.findIndex((item) => item.key === task.status);
  const sla = slaOf(task);
  const version = card?.affectedVersions[0] ?? null;
  const guidance = cleanGuidance((card?.remediation ?? []).join("\n"));
  const fixed = card?.fixedIn[0] ?? guidance.match(/версии\s+([0-9][\w.]*)/)?.[1] ?? null;
  const createdBy = events.find((event) => event.action === "task.created")?.actor || null;
  const evidence = cleanGuidance(String(task.evidence ?? "").trim());

  return (
    <div className="grid items-start gap-3 2xl:grid-cols-[minmax(0,1fr)_280px]">
      <div className="min-w-0 space-y-3">
        <div className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] px-4 py-3">
          <p className="text-[11px] text-[var(--vc-muted)]">Задачи / <span className="font-mono text-[var(--vc-link)]">{key}</span></p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <h2 className="font-mono text-[22px] font-semibold tracking-tight">{key}</h2>
            <Solid text={taskStatusLabel(task.status)} color={statusColor} />
            {priority ? <Solid text={priority.label} color={priority.color} /> : null}
            {(task.stats?.kevCount ?? 0) > 0 ? <Solid text="KEV" color="var(--vc-critical)" /> : null}
          </div>
          <p className="mt-1 text-[15px] font-medium leading-snug">{task.title}</p>
          <p className="mt-1 text-[11px] text-[var(--vc-muted)]">
            Создана: {formatStamp(task.created_at)} · Обновлена: {formatStamp(task.updated_at)}
            {createdBy ? ` · Автор: ${createdBy}` : ""}
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {TRACK.map((item) => {
              const on = task.status === item.key;
              const color = STATUS_COLOR[item.key] ?? "var(--vc-slate)";
              return (
                <button
                  key={item.key}
                  type="button"
                  disabled={busy != null}
                  onClick={() => { if (!on) void save({ status: item.key }, "status"); }}
                  className="h-8 rounded-lg px-3 text-[12px] font-semibold"
                  style={{
                    background: on ? color : "transparent",
                    color: on ? "#fff" : color,
                    border: `1px solid ${color}`,
                    boxShadow: on ? `0 0 14px ${tint(color, 53)}` : undefined
                  }}
                >
                  {item.label}
                </button>
              );
            })}
            <Action disabled={assignDisabled} onClick={assignMe}>Назначить на меня</Action>
            {error ? <span className="text-[12px] text-[var(--vc-danger-text)]">{error}</span> : null}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 lg:grid-cols-3 2xl:grid-cols-6">
          <Meter label="Риск" value={risk == null ? "—" : String(Math.round(risk))} hint="балл задачи 0–100" ratio={risk == null ? 0 : risk / 100} color={riskColor(risk)} />
          <Meter label="CVSS" value={cvss == null ? "—" : cvss.toFixed(1)} hint={band?.label} ratio={cvss == null ? 0 : cvss / 10} color={band?.color ?? "var(--vc-muted)"} />
          <Meter label="EPSS" value={formatEpss(epss)} hint={epss == null ? "нет оценки" : "вероятность"} ratio={epss ?? 0} color="var(--vc-epss)" />
          <Meter label="KEV" value={primary ? (kev ? "да" : "нет") : "—"} hint={kev ? "есть в KEV" : "не в KEV"} ratio={kev ? 1 : 0.08} color={kev ? "var(--vc-critical)" : "var(--vc-faint)"} />
          <Meter label="SLA" value={sla.value} hint={sla.hint} ratio={sla.ratio} color={sla.color} />
          <StageMeter step={step} status={task.status} />
        </div>

        <div className="flex gap-4 overflow-x-auto border-b border-[var(--vc-border)]">
          {([
            ["overview", "Обзор"],
            ["remediation", "Remediation"],
            ["vuln", "Уязвимость"],
            ["activity", "Активность"],
            ["notes", "Статус по уязвимости"],
            ["history", "История"]
          ] as const).map(([id, label]) => (
            <button key={id} type="button" onClick={() => setTab(id)} className={`relative shrink-0 pb-2 text-[13px] ${tab === id ? "font-medium text-[var(--vc-text)]" : "text-[var(--vc-muted)]"}`}>
              {label}
              {tab === id ? <span className="absolute inset-x-0 bottom-0 h-0.5 rounded-full bg-[var(--vc-primary)]" /> : null}
            </button>
          ))}
        </div>

        {tab === "overview" ? (
          <div className="grid gap-3 lg:grid-cols-2">
            <Card title="Статус выполнения">
              <Track status={task.status} busy={busy != null} onPick={(status) => void save({ status }, "status")} />
            </Card>
            <Card title="Связанная уязвимость">
              {primary && card ? <VulnStrip cardId={primary.cve_id} card={card} kev={kev} version={version} onOpen={() => openCve(primary.cve_id)} /> : <p className="text-[12px] text-[var(--vc-muted)]">К задаче не привязана CVE.</p>}
            </Card>
            <Card title="Исполнитель и сроки">
              <Assignee
                task={task}
                busy={busy != null}
                onDueDate={(dueDate) => void save({ dueDate }, "due")}
              />
            </Card>
            <div className="lg:col-span-2">
              <Card title="Статус по уязвимости">
                <VulnStatusNotes
                  value={notes}
                  saved={String(task.notes_md ?? "")}
                  busy={busy != null}
                  onChange={setNotes}
                  onSave={() => void save({ notesMd: notes }, "notes")}
                />
              </Card>
            </div>
          </div>
        ) : null}

        {tab === "remediation" ? (
          <Card title="Remediation">
            {fixed ? <p className="mb-2 text-[13px]">Исправленная версия: <span className="font-semibold text-[var(--vc-success)]">{fixed}</span></p> : <p className="mb-2 text-[12px] text-[var(--vc-muted)]">Исправленная версия в источниках не указана.</p>}
            {evidence ? <p className="whitespace-pre-wrap text-[13px] leading-5">{evidence}</p> : null}
            {guidance ? <ul className="mt-2 space-y-1 text-[13px]">{guidance.split("\n").map((line) => <li key={line}>{line}</li>)}</ul> : null}
            {!evidence && !guidance && !fixed ? <p className="text-[12px] text-[var(--vc-muted)]">Рекомендаций по устранению нет.</p> : null}
          </Card>
        ) : null}

        {tab === "vuln" ? (
          <Card title="Уязвимость">
            {primary && card ? <VulnStrip cardId={primary.cve_id} card={card} kev={kev} version={version} onOpen={() => openCve(primary.cve_id)} /> : <p className="text-[12px] text-[var(--vc-muted)]">К задаче не привязана CVE.</p>}
            {cves.length > 1 ? (
              <ul className="mt-3 space-y-1 text-[12px]">
                {cves.map((item) => (
                  <li key={item.cve_id}>
                    <button type="button" className="font-mono text-[var(--vc-link)] hover:underline" onClick={() => openCve(item.cve_id)}>{item.cve_id}</button>
                    <span className="ml-2 text-[var(--vc-muted)]">риск {item.risk_score ?? "—"} · CVSS {item.cvss_base ?? "—"}</span>
                  </li>
                ))}
              </ul>
            ) : null}
          </Card>
        ) : null}

        {tab === "activity" || tab === "history" ? (
          <Card title={tab === "activity" ? "Активность" : "История"}>
            {events.length ? <EventList events={events} /> : <p className="text-[12px] text-[var(--vc-muted)]">Событий нет.</p>}
          </Card>
        ) : null}

        {tab === "notes" ? (
          <Card title="Статус по уязвимости">
            <VulnStatusNotes
              value={notes}
              saved={String(task.notes_md ?? "")}
              busy={busy != null}
              onChange={setNotes}
              onSave={() => void save({ notesMd: notes }, "notes")}
              rows={8}
            />
          </Card>
        ) : null}
      </div>

      <aside className="space-y-3">
        <Card title="Основная информация">
          <Facts rows={[
            ["ID", key],
            ["Статус", taskStatusLabel(task.status)],
            ["Приоритет", priority?.label ?? "—"],
            ["Исполнитель", task.owner || "—"],
            ["Срок", formatDate(task.due_date)],
            ["Создана", formatStamp(task.created_at)],
            ["Обновлена", formatStamp(task.updated_at)],
            ["Автор", createdBy || "—"]
          ]} />
        </Card>
        <Card title="Связанные объекты">
          <Facts rows={[
            ["Продукт", task.product_display || "—"],
            ["Вендор", task.vendor_display || "—"],
            ["Уязвимость", primary?.cve_id ?? "—"],
            ["Версия", version || "—"],
            ["Исправление", fixed || "—"]
          ]} />
        </Card>
        <Card title="Быстрые действия">
          <div className="flex flex-col gap-2">
            <Action disabled={!primary} onClick={() => primary && openCve(primary.cve_id)}>Открыть уязвимость</Action>
            <Action onClick={() => setTab("remediation")}>Открыть remediation</Action>
            <Action disabled={assignDisabled} onClick={assignMe}>Назначить на меня</Action>
            <button type="button" disabled={task.status === "closed" || busy != null} onClick={() => void save({ status: "closed" }, "close")} className="h-8 rounded-lg border border-[var(--vc-critical)] px-3 text-[12px] font-medium text-[var(--vc-danger-text)] disabled:opacity-40">Закрыть задачу</button>
          </div>
        </Card>
        <Card title="Внешние ссылки">
          <Links card={card} cveId={primary?.cve_id ?? null} kev={kev} />
        </Card>
      </aside>
    </div>
  );
}

function cleanGuidance(text: string) {
  return text
    .split(/\n+|(?<=\.)\s+/)
    .map((line) => line.trim())
    .filter((line) => line && !/инвентар|периметр|инфраструктур|сервер|хост|workstation|\basset\b/i.test(line))
    .join("\n");
}

function applyTaskPatch(
  current: { status: string; owner: string | null; due_date?: string | null; notes_md?: string | null },
  body: { owner?: string | null; status?: string; dueDate?: string | null; notesMd?: string },
  email: string | null
) {
  let status = body.status ?? current.status;
  let owner = body.owner !== undefined ? body.owner : current.owner;
  if (body.status === "in_progress" && body.owner === undefined && current.status !== "in_progress") {
    owner = current.owner || email;
  }
  if (body.status === "new" && body.owner === undefined && current.status !== "new") {
    owner = null;
  }
  if (body.owner && status === "new") status = "in_progress";
  return {
    status,
    owner,
    due_date: body.dueDate !== undefined ? body.dueDate : current.due_date ?? null,
    notes_md: body.notesMd !== undefined ? body.notesMd : current.notes_md ?? null
  };
}

function matchFilter(task: LiveTask, filter: FilterId, email: string | null) {
  if (filter === "mine") return Boolean(email) && task.owner === email;
  if (filter === "critical") return task.priority_local === "critical" || (task.score_final ?? 0) >= 90;
  if (filter === "unassigned") return !task.owner && task.status !== "closed";
  if (filter === "overdue") return isOverdue(task);
  if (filter === "kev") return (task.stats?.kevCount ?? 0) > 0;
  return true;
}

function priorityMeta(priority: string | null) {
  const value = String(priority || "").toLowerCase();
  if (value === "critical") return { label: "Критический", color: "var(--vc-critical)" };
  if (value === "high") return { label: "Высокий", color: "var(--vc-high)" };
  if (value === "medium") return { label: "Средний", color: "var(--vc-medium)" };
  if (value === "low") return { label: "Низкий", color: "var(--vc-low)" };
  return null;
}

function riskColor(score: number | null) {
  if (score == null) return "var(--vc-muted)";
  if (score >= 90) return "var(--vc-critical)";
  if (score >= 70) return "var(--vc-high)";
  if (score >= 40) return "var(--vc-medium)";
  return "var(--vc-success)";
}

function slaOf(task: LiveTask) {
  if (!task.due_date || task.status === "closed") return { value: "—", hint: task.status === "closed" ? "задача закрыта" : "срок не задан", ratio: 0, color: "var(--vc-faint)" };
  const due = new Date(task.due_date);
  if (Number.isNaN(due.getTime())) return { value: "—", hint: "срок не задан", ratio: 0, color: "var(--vc-faint)" };
  const days = Math.ceil((due.getTime() - Date.now()) / 86_400_000);
  if (days < 0) return { value: `${Math.abs(days)} дн.`, hint: "срок прошёл", ratio: 1, color: "var(--vc-critical)" };
  if (days === 0) return { value: "сегодня", hint: formatDate(task.due_date), ratio: 0.85, color: "var(--vc-high)" };
  return { value: `${days} дн.`, hint: `до ${formatDate(task.due_date)}`, ratio: Math.min(1, 7 / days), color: days <= 2 ? "var(--vc-high)" : "var(--vc-low)" };
}

function formatStamp(value: string | null | undefined) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("ru-RU", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }).format(date);
}

function Meter({ label, value, hint, ratio, color }: { label: string; value: string; hint?: string; ratio: number; color: string }) {
  const lit = Math.round(Math.min(1, Math.max(0, ratio)) * 12);
  return (
    <div className="overflow-hidden rounded-xl border px-3 py-2.5" style={{ borderColor: tint(color, 40), background: `linear-gradient(165deg, ${tint(color, 20)} 0%, var(--vc-meter-end) 62%)` }}>
      <div className="text-[10px] font-semibold uppercase tracking-wide" style={{ color }}>{label}</div>
      <div className="mt-0.5 text-[22px] font-semibold tabular-nums leading-none" style={{ color }}>{value}</div>
      {hint ? <div className="mt-1 truncate text-[10px] text-[var(--vc-muted)]">{hint}</div> : null}
      <div className="mt-2 flex h-6 items-end gap-[3px]" aria-hidden>
        {Array.from({ length: 12 }, (_, index) => (
          <span key={index} className="w-[5px] rounded-[2px]" style={{ height: `${28 + (index / 11) * 72}%`, background: index < lit ? color : "var(--vc-track)", boxShadow: index < lit ? `0 0 8px ${tint(color, 53)}` : undefined }} />
        ))}
      </div>
    </div>
  );
}

function StageMeter({ step, status }: { step: number; status: string }) {
  const ratio = step < 0 ? 0 : (step + 1) / TRACK.length;
  const color = status === "closed" ? "var(--vc-success)" : "var(--vc-primary)";
  const radius = 16;
  const length = 2 * Math.PI * radius;
  const dash = length * ratio;
  return (
    <div className="overflow-hidden rounded-xl border border-[color-mix(in_srgb,var(--vc-primary)_40%,transparent)] px-3 py-2.5" style={{ background: "linear-gradient(to bottom, color-mix(in srgb, var(--vc-primary) 25%, transparent), var(--vc-meter-end))" }}>
      <div className="text-[10px] font-semibold uppercase tracking-wide text-[var(--vc-link-soft)]">Этап</div>
      <div className="mt-1 flex items-center gap-2">
        <svg width="42" height="42" viewBox="0 0 42 42" aria-hidden>
          <circle cx="21" cy="21" r={radius} fill="none" stroke="var(--vc-track)" strokeWidth="4" />
          <circle cx="21" cy="21" r={radius} fill="none" stroke={color} strokeWidth="4" strokeLinecap="round" strokeDasharray={`${dash} ${length - dash}`} transform="rotate(-90 21 21)" />
          <text x="21" y="24" textAnchor="middle" fill="var(--vc-text)" fontSize="9">{step < 0 ? "—" : `${step + 1}/${TRACK.length}`}</text>
        </svg>
        <div className="text-[12px] font-medium leading-tight">{step < 0 ? taskStatusLabel(status) : TRACK[step]?.label}</div>
      </div>
    </div>
  );
}

function Track({ status, busy, onPick }: { status: string; busy: boolean; onPick: (status: string) => void }) {
  const current = TRACK.findIndex((item) => item.key === status);
  return (
    <ol className="flex items-start justify-between gap-1">
      {TRACK.map((item, index) => {
        const on = current >= 0 && index <= current;
        const active = index === current;
        const color = STATUS_COLOR[item.key] ?? "var(--vc-primary)";
        return (
          <li key={item.key} className="flex min-w-0 flex-1 flex-col items-center text-center">
            <button
              type="button"
              disabled={busy || active}
              onClick={() => onPick(item.key)}
              className="flex flex-col items-center disabled:cursor-default"
            >
              <span className="h-3 w-3 rounded-full" style={{ background: on ? color : "var(--vc-track-strong)", boxShadow: active ? `0 0 10px ${color}` : undefined }} />
              <span className={`mt-2 text-[11px] ${active ? "font-semibold text-[var(--vc-text)]" : "text-[var(--vc-muted)] hover:text-[var(--vc-text)]"}`}>{item.label}</span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function VulnStrip({ cardId, card, kev, version, onOpen }: { cardId: string; card: VulnCard; kev: boolean; version: string | null; onOpen: () => void }) {
  const band = card.severity;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[13px] font-semibold text-[var(--vc-link)]">{cardId}</span>
        {band ? <Solid text={band.label} color={band.color} /> : null}
      </div>
      <p className="mt-1 line-clamp-3 text-[12px] leading-5 text-[var(--vc-text)]">{card.description || card.title || "Описания в записи нет."}</p>
      <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
        <Mini label="Риск" value={card.riskScore == null ? "—" : String(Math.round(card.riskScore))} color={riskColor(card.riskScore)} />
        <Mini label="CVSS" value={card.cvss == null ? "—" : card.cvss.toFixed(1)} color={band?.color ?? "var(--vc-muted)"} />
        <Mini label="EPSS" value={formatEpss(card.epss)} color="var(--vc-epss)" />
        <Mini label="KEV" value={kev ? "да" : "нет"} color={kev ? "var(--vc-critical)" : "var(--vc-faint)"} />
      </div>
      <div className="mt-2 text-[12px] text-[var(--vc-muted)]">
        {card.product || "продукт не указан"}{version ? ` · ${version}` : ""}{card.vendor ? ` · ${card.vendor}` : ""}
      </div>
      <button type="button" onClick={onOpen} className="mt-3 h-8 rounded-lg bg-[#2f6bff] px-3 text-[12px] font-medium text-white">Открыть уязвимость</button>
    </div>
  );
}

function Assignee({
  task,
  busy,
  onDueDate
}: {
  task: LiveTask;
  busy: boolean;
  onDueDate: (dueDate: string | null) => void;
}) {
  const sla = slaOf(task);
  const initials = task.owner ? task.owner.slice(0, 2).toUpperCase() : "—";
  const dueValue = task.due_date ? String(task.due_date).slice(0, 10) : "";
  return (
    <div className="space-y-3">
      <div className="flex items-start gap-3">
        <span className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-[color-mix(in_srgb,var(--vc-primary)_30%,transparent)] text-[11px] font-semibold text-[var(--vc-on-soft)]">{initials}</span>
        <div className="min-w-0 text-[12px]">
          <div className="font-medium">{task.owner || "Не назначен"}</div>
          <div className="mt-0.5" style={{ color: sla.color }}>SLA: {sla.value}{sla.hint ? ` · ${sla.hint}` : ""}</div>
        </div>
      </div>
      <label className="block text-[11px] text-[var(--vc-muted)]">
        Срок выполнения
        <input
          type="date"
          key={`due-${task.id}-${dueValue}`}
          defaultValue={dueValue}
          disabled={busy}
          onBlur={(event) => {
            const next = event.target.value ? new Date(event.target.value).toISOString() : null;
            const prev = task.due_date ? String(task.due_date).slice(0, 10) : "";
            if ((next ? next.slice(0, 10) : "") === prev) return;
            onDueDate(next);
          }}
          className="mt-1 h-8 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset-2)] px-2 text-[13px] text-[var(--vc-text)] outline-none disabled:opacity-40"
        />
      </label>
    </div>
  );
}

function VulnStatusNotes({
  value,
  saved,
  busy,
  onChange,
  onSave,
  rows = 4
}: {
  value: string;
  saved: string;
  busy: boolean;
  onChange: (value: string) => void;
  onSave: () => void;
  rows?: number;
}) {
  return (
    <div>
      <p className="mb-2 text-[11px] text-[var(--vc-muted)]">Что сделано / что планируется по уязвимости в рамках этой задачи.</p>
      <textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        rows={rows}
        className="w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset-2)] px-3 py-2 text-[13px] text-[var(--vc-text)] outline-none"
        placeholder="Например: патч согласован, ждём окно; хосты в периметре проверены…"
      />
      <button
        type="button"
        disabled={busy || value === saved}
        onClick={onSave}
        className="mt-2 h-8 rounded-lg bg-[#2f6bff] px-3 text-[12px] font-medium text-white disabled:opacity-40"
      >
        Сохранить статус
      </button>
    </div>
  );
}

function EventList({ events }: { events: TaskEvent[] }) {
  return (
    <ul className="space-y-2">
      {events.map((event) => (
        <li key={event.id} className="rounded-lg border border-[var(--vc-line-mid)] px-3 py-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-[12px] font-medium">{eventLabel(event.action)}</span>
            <span className="text-[11px] text-[var(--vc-muted)]">{formatStamp(event.ts)}</span>
          </div>
          <div className="mt-0.5 text-[11px] text-[var(--vc-muted)]">{event.actor || "без автора"}{eventDetail(event) ? ` · ${eventDetail(event)}` : ""}</div>
        </li>
      ))}
    </ul>
  );
}

function eventLabel(action: string) {
  if (action === "task.created") return "Задача создана";
  if (action === "task.updated") return "Задача изменена";
  if (action === "task.cves.added") return "Привязаны CVE";
  if (action === "task.cves.removed") return "CVE убрана";
  return action;
}

function eventDetail(event: TaskEvent) {
  const after = record(event.after);
  const before = record(event.before);
  if (!after) return "";
  const parts: string[] = [];
  if (after.status && after.status !== before?.status) {
    parts.push(`${taskStatusLabel(String(before?.status ?? "—"))} → ${taskStatusLabel(String(after.status))}`);
  }
  if ("owner" in after && after.owner !== before?.owner) {
    parts.push(after.owner ? `исполнитель ${String(after.owner)}` : "исполнитель снят");
  }
  if (Array.isArray(after.cveIds)) parts.push(after.cveIds.map(String).join(", "));
  if (typeof after.cveId === "string") parts.push(after.cveId);
  return parts.join(" · ");
}

function record(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function Links({ card, cveId, kev }: { card: VulnCard | null; cveId: string | null; kev: boolean }) {
  const links: Array<{ label: string; href: string }> = [];
  if (cveId) links.push({ label: "NVD", href: card?.links.nvd || `https://nvd.nist.gov/vuln/detail/${cveId}` });
  if (card?.links.epss) links.push({ label: "EPSS", href: card.links.epss });
  if (kev && card?.links.kev) links.push({ label: "CISA KEV", href: card.links.kev });
  for (const item of card?.advisories ?? []) links.push({ label: item.title || "Advisory", href: item.link });
  for (const item of card?.bdu ?? []) links.push({ label: item.id, href: `https://bdu.fstec.ru/vul/${encodeURIComponent(item.id)}` });
  const unique = links.filter((item, index) => item.href && links.findIndex((other) => other.href === item.href) === index).slice(0, 8);
  if (!unique.length) return <p className="text-[12px] text-[var(--vc-muted)]">Ссылок нет.</p>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {unique.map((item) => (
        <a key={item.href} href={item.href} target="_blank" rel="noreferrer" className="rounded-md border border-[var(--vc-border)] px-2 py-1 text-[11px] text-[var(--vc-link)] hover:border-[var(--vc-primary)]">{item.label}</a>
      ))}
    </div>
  );
}

function Facts({ rows }: { rows: Array<[string, string]> }) {
  return (
    <dl className="space-y-1.5">
      {rows.map(([label, value]) => (
        <div key={label} className="flex items-start justify-between gap-3 border-b border-[var(--vc-line)] py-1">
          <dt className="text-[11px] uppercase tracking-wide text-[var(--vc-muted)]">{label}</dt>
          <dd className="max-w-[62%] text-right text-[12px] font-medium">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-3">
      <h3 className="mb-2 text-[13px] font-semibold">{title}</h3>
      {children}
    </section>
  );
}

function Solid({ text, color }: { text: string; color: string }) {
  return <span className="rounded-md px-2 py-0.5 text-[11px] font-semibold text-white" style={{ background: color }}>{text}</span>;
}

function Mini({ label, value, color }: { label: string; value: string; color: string }) {
  return <span className="rounded-md px-1.5 py-0.5 font-semibold text-white" style={{ background: color }}>{label} {value}</span>;
}

function Action({ children, onClick, disabled }: { children: ReactNode; onClick: () => void; disabled?: boolean }) {
  return <button type="button" disabled={disabled} onClick={onClick} className="h-8 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset-2)] px-3 text-[12px] font-medium hover:border-[var(--vc-primary)] disabled:opacity-40">{children}</button>;
}

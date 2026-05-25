import { Injectable, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import amqplib, { Channel, ChannelModel, ConsumeMessage } from "amqplib";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import os from "node:os";
import fs from "node:fs/promises";
import path from "node:path";
import { DbService } from "../services/db.service.js";

type AsvMsfRequestedEnvelope = {
  type?: string;
  payload?: { runId?: string };
  [k: string]: unknown;
};

function capText(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n\n[truncated]\n`;
}

function isTruthy(v: unknown): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    return s === "1" || s === "true" || s === "yes" || s === "y";
  }
  return false;
}

function parseMsfSearchModules(stdout: string): string[] {
  const lines = stdout.split("\n");
  const out: string[] = [];
  for (const raw of lines) {
    const line = raw.trim();
    // Typical search output: "25   auxiliary/scanner/http/citrix_bleed_cve_2023_4966  2023-10-25 ..."
    const m = line.match(/^\d+\s+((?:auxiliary|exploit)\/[a-z0-9_/-]+)\s+/i);
    if (m?.[1]) out.push(m[1]);
  }
  // Sometimes output prints module path without index; keep a fallback.
  for (const raw of lines) {
    const line = raw.trim();
    if (/^(auxiliary|exploit)\/[a-z0-9_/-]+$/i.test(line)) out.push(line);
  }
  const uniq = [...new Set(out.map((s) => s.trim()).filter(Boolean))];
  return uniq.slice(0, 200);
}

function guessKeywordsFromPort(port: number | null): string[] {
  if (!port) return [];
  if (port === 21) return ["ftp"];
  if (port === 22) return ["ssh"];
  if (port === 23) return ["telnet"];
  if (port === 25 || port === 587 || port === 465) return ["smtp"];
  if (port === 53) return ["dns"];
  if (port === 80 || port === 443 || port === 8080 || port === 8443) return ["http", "web", "ssl"];
  if (port === 445 || port === 139) return ["smb", "samba", "ms17", "eternalblue"];
  if (port === 3389) return ["rdp"];
  if (port === 1433) return ["mssql"];
  if (port === 1521) return ["oracle"];
  if (port === 3306) return ["mysql"];
  if (port === 5432) return ["postgres"];
  if (port === 6379) return ["redis"];
  if (port === 27017) return ["mongo"];
  if (port === 161) return ["snmp"];
  return [];
}

function scoreModule(mod: string, hints: { wantExploit: boolean; keywords: string[] }): number {
  const m = mod.toLowerCase();
  let s = 0;
  if (hints.wantExploit) {
    if (m.startsWith("exploit/")) s += 40;
    if (m.startsWith("auxiliary/")) s += 5;
  } else {
    if (m.startsWith("auxiliary/scanner/")) s += 40;
    if (m.startsWith("auxiliary/")) s += 20;
    if (m.startsWith("exploit/")) s -= 30;
  }
  for (const k of hints.keywords) {
    if (k && m.includes(k.toLowerCase())) s += 10;
  }
  if (m.includes("version")) s += 6;
  if (m.includes("login")) s += 3;
  if (m.includes("bruteforce")) s -= 10;
  return s;
}

function pickBestModule(candidates: string[], hints: { wantExploit: boolean; keywords: string[] }): string | null {
  if (!candidates.length) return null;
  let best: { mod: string; score: number } | null = null;
  for (const mod of candidates) {
    const sc = scoreModule(mod, hints);
    if (!best || sc > best.score) best = { mod, score: sc };
  }
  return best?.mod ?? null;
}

type MsfStepResult = {
  step: number;
  label: string;
  module: string;
  requestedAction: "check" | "run" | "exploit";
  actualAction: "check" | "run" | "exploit";
  exitCode: number;
  verdict: "not_applicable" | "likely_vulnerable" | "not_vulnerable" | "unknown" | "error";
  conclusion: string;
  highlights: string[];
  sessionsHint: string | null;
  lootHint: string | null;
};

function verdictRank(v: MsfStepResult["verdict"]): number {
  // Higher means "stronger / more actionable" signal.
  // likely_vulnerable > not_vulnerable > not_applicable > unknown > error
  switch (v) {
    case "likely_vulnerable":
      return 50;
    case "not_vulnerable":
      return 40;
    case "not_applicable":
      return 30;
    case "unknown":
      return 20;
    case "error":
      return 10;
    default:
      return 0;
  }
}

function versionScannerForPort(port: number | null): string | null {
  if (!port) return null;
  if (port === 21) return "auxiliary/scanner/ftp/ftp_version";
  if (port === 22) return "auxiliary/scanner/ssh/ssh_version";
  if (port === 25) return "auxiliary/scanner/smtp/smtp_version";
  if (port === 110) return "auxiliary/scanner/pop3/pop3_version";
  if (port === 143) return "auxiliary/scanner/imap/imap_version";
  if (port === 445) return "auxiliary/scanner/smb/smb_version";
  if (port === 3389) return "auxiliary/scanner/rdp/rdp_scanner";
  if (port === 80 || port === 443 || port === 8080 || port === 8443) return "auxiliary/scanner/http/http_version";
  return null;
}

function buildChainSteps(opts: {
  selectedModule: string;
  selectedAction: "check" | "run" | "exploit";
  wantExploit: boolean;
  cve: string | null;
  keywords: string[];
  candidates: string[];
  rport: number | null;
  maxSteps: number;
}): Array<{ label: string; module: string; action: "check" | "run" | "exploit" }> {
  const steps: Array<{ label: string; module: string; action: "check" | "run" | "exploit" }> = [];

  const ver = versionScannerForPort(opts.rport);
  if (ver) steps.push({ label: "version/banner", module: ver, action: "run" });

  steps.push({ label: "autopick", module: opts.selectedModule, action: opts.selectedAction });

  if (opts.wantExploit) {
    const exploitKeywords = [...opts.keywords, opts.cve ?? ""].filter(Boolean);
    const exploitPick = pickBestModule(opts.candidates, { wantExploit: true, keywords: exploitKeywords });
    const exploitModule = exploitPick && exploitPick !== opts.selectedModule ? exploitPick : opts.selectedModule.startsWith("exploit/") ? opts.selectedModule : null;
    if (exploitModule) steps.push({ label: "exploit(optional)", module: exploitModule, action: "exploit" });
  }

  // De-dup while preserving order.
  const seen = new Set<string>();
  const uniq = steps.filter((s) => {
    const k = `${s.action}::${s.module}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return uniq.slice(0, Math.max(1, opts.maxSteps));
}

function buildRc(opts: {
  action: "search" | "check" | "run" | "exploit";
  module: string | null;
  cve: string | null;
  findingTitle: string;
  rhosts: string | null;
  rport: number | null;
  ssl: boolean | null;
  vhost: string | null;
  targetUri: string | null;
}): string {
  const lines: string[] = [];
  lines.push(`# vip asv metasploit rc`);
  lines.push(`# generated_at=${new Date().toISOString()}`);
  lines.push(`# title=${opts.findingTitle.replaceAll("\n", " ").slice(0, 200)}`);
  if (opts.cve) lines.push(`# cve=${opts.cve}`);
  lines.push("");
  lines.push("setg VERBOSE true");
  lines.push("setg ExitOnSession false");
  if (opts.rhosts) lines.push(`setg RHOSTS ${opts.rhosts}`);
  if (opts.rport != null) lines.push(`setg RPORT ${opts.rport}`);
  if (opts.ssl != null) lines.push(`setg SSL ${opts.ssl ? "true" : "false"}`);
  if (opts.vhost) lines.push(`setg VHOST ${opts.vhost}`);
  lines.push("");

  if (opts.action === "search") {
    if (opts.cve) lines.push(`search cve:${opts.cve}`);
    if (opts.module) lines.push(`search ${opts.module}`);
    lines.push("search type:auxiliary name:scanner");
    lines.push("exit -y");
    return lines.join("\n") + "\n";
  }

  if (opts.module) {
    lines.push(`use ${opts.module}`);
  } else if (opts.cve) {
    lines.push(`# no module selected; searching by CVE`);
    lines.push(`search cve:${opts.cve}`);
    lines.push("exit -y");
    return lines.join("\n") + "\n";
  } else {
    lines.push(`# no module selected; nothing to run`);
    lines.push("exit -y");
    return lines.join("\n") + "\n";
  }

  if (opts.targetUri) lines.push(`set TARGETURI ${opts.targetUri}`);
  lines.push("show options");
  lines.push("");

  if (opts.action === "check") {
    lines.push("check");
  } else if (opts.action === "run") {
    lines.push("run");
  } else {
    // exploit
    // -z: do not interact with session; best-effort reduce risk of leaving sessions.
    lines.push("exploit -z");
  }
  // Always print post-run signals so we can build a verdict without reading raw logs.
  lines.push("");
  lines.push('echo "=== vip:postrun:sessions ==="');
  lines.push("sessions -l");
  lines.push('echo "=== vip:postrun:creds ==="');
  lines.push("creds");
  lines.push('echo "=== vip:postrun:loot ==="');
  lines.push("loot");
  lines.push("exit -y");
  return lines.join("\n") + "\n";
}

function summarizeMsfOutput(
  ctx: { action: "search" | "check" | "run" | "exploit"; module: string | null },
  stdout: string,
  stderr: string
): {
  verdict: "not_applicable" | "unknown" | "likely_vulnerable" | "not_vulnerable" | "error";
  signals: { plus: number; minus: number; bang: number };
  highlights: string[];
  conclusion: string;
  sessionsHint: string | null;
  lootHint: string | null;
} {
  const out = `${stdout}\n${stderr}`.split("\n").map((l) => l.trimEnd());
  const plus = out.filter((l) => l.startsWith("[+]")).length;
  const minus = out.filter((l) => l.startsWith("[-]")).length;
  const bang = out.filter((l) => l.startsWith("[!]")).length;

  const hi = out
    .filter((l) => l.startsWith("[+]") || l.startsWith("[!]") || l.startsWith("[-]") || l.toLowerCase().includes("vulnerable"))
    .filter((l) => l.length > 0)
    .slice(-24);

  const idxSessions = out.findIndex((l) => l.includes("=== vip:postrun:sessions ==="));
  const idxCreds = out.findIndex((l) => l.includes("=== vip:postrun:creds ==="));
  const idxLoot = out.findIndex((l) => l.includes("=== vip:postrun:loot ==="));

  const section = (startIdx: number, endIdx: number): string[] => {
    if (startIdx < 0) return [];
    const end = endIdx > startIdx ? endIdx : out.length;
    return out.slice(startIdx + 1, end).map((s) => s.trim()).filter(Boolean);
  };

  const sessionsSec = section(idxSessions, idxCreds);
  const credsSec = section(idxCreds, idxLoot);
  const lootSec = section(idxLoot, out.length);

  const sessionsHint =
    sessionsSec.find((l) => /session\s+\d+/i.test(l)) ??
    sessionsSec.find((l) => /no active sessions|no sessions/i.test(l)) ??
    null;
  const lootHint =
    lootSec.find((l) => /loot/i.test(l) && !l.includes("=== vip:postrun:loot ===")) ??
    credsSec.find((l) => /creds|credential/i.test(l)) ??
    null;

  const sessionsCount =
    sessionsSec.filter((l) => /^\d+\s+/.test(l) || /session\s+\d+/i.test(l)).length;

  const joined = out.join("\n").toLowerCase();

  if (ctx.action === "search") {
    return {
      verdict: "not_applicable",
      signals: { plus, minus, bang },
      highlights: hi.slice(-14),
      conclusion: "Это режим search: он ищет модули Metasploit и не подтверждает применимость/уязвимость.",
      sessionsHint: null,
      lootHint: null
    };
  }

  // module may be auto-picked; if missing here, treat as not applicable.
  if (!ctx.module) {
    return {
      verdict: "not_applicable",
      signals: { plus, minus, bang },
      highlights: hi.slice(-14),
      conclusion: "Модуль не выбран/не удалось подобрать автоматически: без module нельзя дать ответ по применимости.",
      sessionsHint: null,
      lootHint: null
    };
  }

  if (joined.includes("su-exec: msfconsole") || joined.includes("command not found")) {
    return {
      verdict: "error",
      signals: { plus, minus, bang },
      highlights: hi,
      conclusion: "Metasploit не запустился (msfconsole не найден/не стартовал).",
      sessionsHint,
      lootHint
    };
  }

  // If exploit/run created sessions, treat as strong success signal.
  if ((ctx.action === "exploit" || ctx.action === "run") && sessionsCount > 0) {
    return {
      verdict: "likely_vulnerable",
      signals: { plus, minus, bang },
      highlights: hi,
      conclusion: `Создана сессия Metasploit (${sessionsCount}). Это сильный признак успешной эксплуатации/выполнения модуля.`,
      sessionsHint: sessionsHint ?? `sessions=${sessionsCount}`,
      lootHint
    };
  }

  // Explicit check-not-supported: tell user to use run (not "unknown").
  if (ctx.action === "check" && joined.includes("does not support check")) {
    return {
      verdict: "not_applicable",
      signals: { plus, minus, bang },
      highlights: hi,
      conclusion: "Выбранный модуль НЕ поддерживает check. Используй action=run (safe) или action=exploit (с подтверждением), либо выбери другой scanner-модуль с check.",
      sessionsHint,
      lootHint
    };
  }
  if (joined.includes("is vulnerable") || joined.includes("vulnerable!") || joined.includes("session created")) {
    return {
      verdict: "likely_vulnerable",
      signals: { plus, minus, bang },
      highlights: hi,
      conclusion: "Похоже, уязвимость подтверждается (в выводе есть явные признаки successful exploit/check).",
      sessionsHint,
      lootHint
    };
  }
  if (joined.includes("is not vulnerable") || joined.includes("not vulnerable") || joined.includes("does not appear to be vulnerable")) {
    return {
      verdict: "not_vulnerable",
      signals: { plus, minus, bang },
      highlights: hi,
      conclusion: "Похоже, цель НЕ уязвима для выбранного модуля/проверки (в выводе есть not vulnerable).",
      sessionsHint,
      lootHint
    };
  }

  // Banner / version-only scanners: treat as applicability validated (not vuln).
  if (joined.includes("ftp banner") || joined.includes("http server") || joined.includes("version")) {
    const findLast = (pred: (l: string) => boolean): string | null => {
      for (let i = out.length - 1; i >= 0; i--) {
        const l = out[i] ?? "";
        if (pred(l)) return l;
      }
      return null;
    };
    const bannerLine =
      findLast((l) => l.toLowerCase().includes("banner")) ??
      findLast((l) => l.startsWith("[+]") && /version|banner/i.test(l)) ??
      null;
    return {
      verdict: "not_vulnerable",
      signals: { plus, minus, bang },
      highlights: hi,
      conclusion: bannerLine
        ? `Сервис отвечает, модуль применим. По результату это версия/баннер без явного признака уязвимости: ${bannerLine.slice(0, 200)}`
        : "Сервис отвечает, модуль применим. Явных признаков уязвимости не найдено (версия/баннер).",
      sessionsHint,
      lootHint
    };
  }

  if (joined.includes("exploit completed") && joined.includes("no session was created")) {
    return {
      verdict: "unknown",
      signals: { plus, minus, bang },
      highlights: hi,
      conclusion: "Exploit отработал, но сессия не создана. Это может означать, что цель не уязвима, либо эксплойт не применим/не удалось доставить payload. Смотри sessions/loot в итогах.",
      sessionsHint,
      lootHint
    };
  }
  return {
    verdict: "unknown",
    signals: { plus, minus, bang },
    highlights: hi,
    conclusion:
      "Модуль отработал, но явных маркеров уязвимости/неуязвимости не найдено. Обычно это означает, что модуль не умеет check, либо параметры/цель не подходят. Мы добавили post-run sections (sessions/creds/loot) — проверь их в highlights.",
    sessionsHint,
    lootHint
  };
}

async function runDockerAndCapture(opts: {
  cmd: string;
  args: string[];
  timeoutMs: number;
  onTimeout?: () => void;
}): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const stdoutChunks: string[] = [];
  const stderrChunks: string[] = [];
  let child: ReturnType<typeof spawn> | null = null;

  const exitCode = await Promise.race([
    new Promise<number>((resolve) => {
      child = spawn(opts.cmd, opts.args, { stdio: ["ignore", "pipe", "pipe"] });
      child.stdout?.on("data", (d) => {
        if (stdoutChunks.join("").length > 1_000_000) return;
        stdoutChunks.push(d.toString("utf8"));
      });
      child.stderr?.on("data", (d) => {
        if (stderrChunks.join("").length > 1_000_000) return;
        stderrChunks.push(d.toString("utf8"));
      });
      child.on("error", (err) => {
        stderrChunks.push(err instanceof Error ? err.message : String(err));
        resolve(1);
      });
      child.on("exit", (code) => resolve(code ?? 1));
    }),
    new Promise<number>((resolve) =>
      setTimeout(() => {
        try {
          child?.kill("SIGKILL");
        } catch {
          // ignore
        }
        try {
          opts.onTimeout?.();
        } catch {
          // ignore
        }
        resolve(124);
      }, Math.max(1_000, opts.timeoutMs))
    )
  ]);

  return { exitCode, stdout: stdoutChunks.join(""), stderr: stderrChunks.join("") };
}

@Injectable()
export class AsvMsfWorker implements OnModuleInit, OnModuleDestroy {
  private conn?: ChannelModel;
  private ch?: Channel;

  constructor(private readonly db: DbService) {}

  async onModuleInit() {
    const url = process.env.RABBITMQ_URL ?? "amqp://vuln:vuln@localhost:5672/";
    this.conn = await amqplib.connect(url);
    this.ch = await this.conn.createChannel();
    await this.ensureTopology();
    await this.ch.prefetch(1);
    await this.ch.consume("asv.msf", (msg) => void this.handleMessage(msg), { noAck: false });
    // eslint-disable-next-line no-console
    console.log("[asv:msf] worker ready queue=asv.msf prefetch=1");
  }

  private async ensureTopology() {
    if (!this.ch) throw new Error("channel not initialized");
    const ch = this.ch;
    await ch.assertExchange("vuln.events", "topic", { durable: true });
    await ch.assertExchange("vuln.dlx", "topic", { durable: true });
    await ch.assertQueue("asv.msf", {
      durable: true,
      arguments: {
        "x-dead-letter-exchange": "vuln.dlx",
        "x-dead-letter-routing-key": "dlq.asv.msf"
      }
    });
    await ch.bindQueue("asv.msf", "vuln.events", "asv.msf.requested.*");
    await ch.assertQueue("dlq.asv.msf", { durable: true });
    await ch.bindQueue("dlq.asv.msf", "vuln.dlx", "dlq.asv.msf");
  }

  private ack(msg: ConsumeMessage) {
    if (!this.ch) throw new Error("channel not initialized");
    this.ch.ack(msg);
  }

  private nack(msg: ConsumeMessage, requeue = false) {
    if (!this.ch) throw new Error("channel not initialized");
    this.ch.nack(msg, false, requeue);
  }

  private async writeArtifact(runId: string, kind: "msf.stdout" | "msf.stderr" | "msf.rc" | "msf.meta", content: string) {
    const truncated = capText(content ?? "", 2_000_000);
    const bytes = Buffer.byteLength(truncated, "utf8");
    const sha256 = createHash("sha256").update(truncated).digest("hex");
    await this.db.query(
      `INSERT INTO asv_msf_artifact (run_id, kind, bytes, sha256, storage, content_text)
       VALUES ($1,$2,$3,$4,'inline',$5)`,
      [runId, kind, bytes, sha256, truncated]
    );
  }

  private async logEvent(runId: string, action: string, actor: string | null, before?: unknown, after?: unknown, meta?: unknown) {
    await this.db.query(
      `INSERT INTO asv_msf_event (run_id, actor, action, before, after, meta)
       VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb)`,
      [runId, actor, action, before ? JSON.stringify(before) : null, after ? JSON.stringify(after) : null, JSON.stringify(meta ?? {})]
    );
  }

  private async handleMessage(msg: ConsumeMessage | null) {
    if (!msg) return;
    const raw = msg.content.toString("utf8");
    let env: AsvMsfRequestedEnvelope;
    try {
      env = JSON.parse(raw) as AsvMsfRequestedEnvelope;
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn(`[asv:msf] bad json, dropping: ${e instanceof Error ? e.message : String(e)}`);
      this.ack(msg);
      return;
    }

    const runId = env?.payload?.runId;
    if (!runId || typeof runId !== "string") {
      // eslint-disable-next-line no-console
      console.warn("[asv:msf] missing payload.runId, dropping");
      this.ack(msg);
      return;
    }

    const runRow = await this.db.query<{
      id: string;
      finding_id: string;
      scan_run_id: string | null;
      asset_id: string | null;
      status: string;
      mode: "safe" | "exploit";
      action: "search" | "check" | "run" | "exploit";
      module: string | null;
      options: any;
      ack_risks: boolean;
      created_by: string | null;
    }>(
      `SELECT id, finding_id, scan_run_id, asset_id, status, mode, action, module, options, ack_risks, created_by
         FROM asv_msf_run
        WHERE id = $1`,
      [runId]
    );
    const run = runRow.rows[0];
    if (!run) {
      this.ack(msg);
      return;
    }
    if (run.status !== "queued") {
      this.ack(msg);
      return;
    }

    const enabled = process.env.MSF_ENABLED !== "0";
    if (!enabled) {
      await this.db.query(
        `UPDATE asv_msf_run SET status='failed', error=$2, ended_at=now(), updated_at=now() WHERE id=$1`,
        [runId, "MSF_ENABLED=0 (runner disabled)"]
      );
      await this.logEvent(runId, "failed", run.created_by ?? null, { status: "queued" }, { status: "failed" }, { reason: "disabled" });
      this.ack(msg);
      return;
    }

    if (run.mode === "exploit" && !run.ack_risks) {
      await this.db.query(
        `UPDATE asv_msf_run SET status='failed', error=$2, ended_at=now(), updated_at=now() WHERE id=$1`,
        [runId, "exploit mode requires ack_risks=true"]
      );
      await this.logEvent(runId, "failed", run.created_by ?? null, { status: "queued" }, { status: "failed" }, { reason: "ack_required" });
      this.ack(msg);
      return;
    }

    const findingRow = await this.db.query<{ title: string; evidence: any; affected: any }>(
      `SELECT title, evidence, affected FROM asv_finding WHERE id = $1`,
      [run.finding_id]
    );
    const finding = findingRow.rows[0];
    const blob = [
      finding?.title ?? "",
      JSON.stringify(finding?.affected ?? {}),
      JSON.stringify(finding?.evidence ?? [])
    ].join("\n");
    const cve = (blob.match(/CVE-\\d{4}-\\d{4,7}/i)?.[0] ?? "").toUpperCase() || null;

    const options = run.options && typeof run.options === "object" ? (run.options as Record<string, unknown>) : {};
    const autoPick = Boolean(options.autoPick === true);
    const rhosts = typeof options.RHOSTS === "string" ? options.RHOSTS.trim() : null;
    const rport = Number.isFinite(Number(options.RPORT)) ? Math.floor(Number(options.RPORT)) : null;
    const ssl = options.SSL == null ? null : isTruthy(options.SSL);
    const vhost = typeof options.VHOST === "string" ? options.VHOST.trim() : null;
    const targetUri = typeof options.TARGETURI === "string" ? options.TARGETURI.trim() : null;

    const image = process.env.MSF_IMAGE?.trim() || "metasploitframework/metasploit-framework:latest";
    const maxMs = Math.max(10_000, Math.min(900_000, Number(process.env.MSF_MAX_MS ?? 240_000)));
    const containerName = `vip-asv-msf-${runId.slice(0, 8)}-${randomUUID().slice(0, 8)}`;
    const msfconsolePath = process.env.MSF_MSFCONSOLE_PATH?.trim() || "/usr/src/metasploit-framework/msfconsole";
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vip-asv-msf-"));
    const rcPath = path.join(dir, "run.rc");

    // Auto-pick module if requested and module is empty.
    let selectedModule = run.module?.trim() ? run.module.trim() : null;
    let selectedAction: "check" | "run" | "exploit" | "search" = run.action;
    let autoMeta: Record<string, unknown> | null = null;
    let autoCandidates: string[] = [];
    let autoKeywords: string[] = [];

    if (autoPick && !selectedModule && (run.action === "check" || run.action === "run" || run.action === "exploit")) {
      // Ensure image exists before search.
      const inspect = await runDockerAndCapture({ cmd: "docker", args: ["image", "inspect", image], timeoutMs: 15_000 });
      if (inspect.exitCode !== 0) {
        await runDockerAndCapture({
          cmd: "docker",
          args: ["pull", image],
          timeoutMs: Math.max(30_000, Math.min(900_000, Math.floor(maxMs / 2)))
        });
      }

      const keywords = [...new Set([...guessKeywordsFromPort(rport), run.mode === "exploit" ? "exploit" : "scanner"])].slice(0, 6);
      autoKeywords = keywords;
      const wantExploit = run.mode === "exploit" || run.action === "exploit";

      const queries: string[] = [];
      if (cve) queries.push(`search cve:${cve}`);
      // Add a focused scanner search; cheaper than dumping whole module list.
      queries.push(`search type:auxiliary name:scanner`);
      for (const k of keywords) {
        if (k && k !== "scanner") queries.push(`search ${k}`);
      }
      const queryScript = queries.join("; ");

      const searchArgs = [
        "run",
        "--rm",
        "--name",
        `${containerName}-search`,
        "-i",
        image,
        msfconsolePath,
        "-q",
        "-x",
        `${queryScript}; exit -y`
      ];
      const searchRes = await runDockerAndCapture({ cmd: "docker", args: searchArgs, timeoutMs: Math.max(30_000, Math.min(180_000, Math.floor(maxMs / 2))) });
      const candidates = parseMsfSearchModules(searchRes.stdout);
      autoCandidates = candidates;
      selectedModule = pickBestModule(candidates, { wantExploit, keywords });
      autoMeta = { autoPick: true, wantExploit, keywords, cve, queries, candidates: candidates.slice(0, 30), selectedModule };

      if (!selectedModule) {
        await this.db.query(
          `UPDATE asv_msf_run SET status='failed', error=$2, ended_at=now(), updated_at=now() WHERE id=$1`,
          [runId, "autoPick failed: no suitable module found"]
        );
        await this.logEvent(runId, "failed", run.created_by ?? null, { status: "running" }, { status: "failed" }, { ...autoMeta, reason: "no_module" });
        await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
        this.ack(msg);
        return;
      }

      await this.db.query(`UPDATE asv_msf_run SET module=$2, updated_at=now() WHERE id=$1`, [runId, selectedModule]);
      await this.logEvent(runId, "auto_picked_module", run.created_by ?? null, null, null, autoMeta);
    }

    await this.db.query(
      `UPDATE asv_msf_run
          SET status='running', started_at=COALESCE(started_at, now()), updated_at=now(), error=NULL
        WHERE id=$1`,
      [runId]
    );
    await this.logEvent(runId, "started", run.created_by ?? null, { status: "queued" }, { status: "running" });

    try {
      // Ensure image exists locally; pull if missing (keeps the actual run logs cleaner).
      const inspect2 = await runDockerAndCapture({ cmd: "docker", args: ["image", "inspect", image], timeoutMs: 15_000 });
      if (inspect2.exitCode !== 0) {
        const pull = await runDockerAndCapture({ cmd: "docker", args: ["pull", image], timeoutMs: Math.max(30_000, Math.min(900_000, Math.floor(maxMs / 2))) });
        if (pull.exitCode !== 0) {
          await this.writeArtifact(runId, "msf.stderr", pull.stderr || pull.stdout || "docker pull failed");
          await this.db.query(`UPDATE asv_msf_run SET status='failed', error=$2, ended_at=now(), updated_at=now() WHERE id=$1`, [
            runId,
            capText(pull.stderr || pull.stdout || "docker pull failed", 2000)
          ]);
          await this.logEvent(runId, "failed", run.created_by ?? null, { status: "running" }, { status: "failed" }, { step: "pull", exitCode: pull.exitCode });
          await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
          this.ack(msg);
          return;
        }
      }

      const dockerBaseArgs: string[] = [
        "run",
        "--rm",
        "--label",
        `vip.asv.msf_run_id=${runId}`,
        "-v",
        `${dir}:/work`,
        "-i"
      ];
      if (process.platform !== "darwin") dockerBaseArgs.push("--network", "host");

      const chainEnabled =
        autoPick &&
        isTruthy(process.env.MSF_CHAIN_ENABLED ?? "1") &&
        (run.action === "check" || run.action === "run" || run.action === "exploit");
      const maxSteps = Math.max(1, Math.min(5, Number(process.env.MSF_CHAIN_MAX_STEPS ?? 3)));
      const wantExploit = run.mode === "exploit" || run.action === "exploit";

      const stepsPlan =
        chainEnabled && selectedModule && selectedAction !== "search"
          ? buildChainSteps({
              selectedModule,
              selectedAction,
              wantExploit,
              cve,
              keywords: autoKeywords.length ? autoKeywords : guessKeywordsFromPort(rport),
              candidates: autoCandidates.length ? autoCandidates : [selectedModule],
              rport,
              maxSteps
            })
          : selectedModule && selectedAction !== "search"
            ? [{ label: "single", module: selectedModule, action: selectedAction }]
            : [];

      await this.writeArtifact(
        runId,
        "msf.meta",
        JSON.stringify(
          {
            runId,
            mode: run.mode,
            action: run.action,
            module: run.module,
            cve,
            options: { RHOSTS: rhosts, RPORT: rport, SSL: ssl, VHOST: vhost, TARGETURI: targetUri },
            docker: { image, containerName },
            maxMs,
            autoPick,
            chain: { enabled: chainEnabled, maxSteps, stepsPlan }
          },
          null,
          2
        )
      );

      const combinedStdout: string[] = [];
      const combinedStderr: string[] = [];
      const stepResults: MsfStepResult[] = [];

      const timeoutPerStep = Math.max(15_000, Math.floor(maxMs / Math.max(1, stepsPlan.length)));

      for (let i = 0; i < stepsPlan.length; i++) {
        const step = stepsPlan[i]!;
        let reqAction: "check" | "run" | "exploit" = step.action;
        let actAction: "check" | "run" | "exploit" = reqAction;

        const rc = buildRc({
          action: actAction,
          module: step.module,
          cve,
          findingTitle: finding?.title ?? "ASV finding",
          rhosts,
          rport,
          ssl,
          vhost,
          targetUri
        });
        await fs.writeFile(rcPath, rc, "utf8");

        const stepContainer = `${containerName}-s${i + 1}`;
        const dockerArgs = [
          "run",
          "--rm",
          "--name",
          stepContainer,
          ...dockerBaseArgs.slice(2),
          image,
          msfconsolePath,
          "-q",
          "-r",
          "/work/run.rc"
        ];

        const rr = await runDockerAndCapture({
          cmd: "docker",
          args: dockerArgs,
          timeoutMs: timeoutPerStep,
          onTimeout: () => {
            try {
              spawn("docker", ["rm", "-f", stepContainer], { stdio: ["ignore", "ignore", "ignore"] });
            } catch {
              // ignore
            }
          }
        });

        let stdout = rr.stdout;
        let stderr = rr.stderr;
        let exitCode = rr.exitCode;

        // Per-step fallback check->run.
        const sum1 = summarizeMsfOutput({ action: actAction, module: step.module }, stdout, stderr);
        if (actAction === "check" && sum1.verdict === "not_applicable" && /does not support check/i.test(`${stdout}\n${stderr}`)) {
          actAction = "run";
          const rc2 = buildRc({
            action: actAction,
            module: step.module,
            cve,
            findingTitle: finding?.title ?? "ASV finding",
            rhosts,
            rport,
            ssl,
            vhost,
            targetUri
          });
          await fs.writeFile(rcPath, rc2, "utf8");
          const rr2 = await runDockerAndCapture({
            cmd: "docker",
            args: dockerArgs,
            timeoutMs: timeoutPerStep,
            onTimeout: () => {
              try {
                spawn("docker", ["rm", "-f", stepContainer], { stdio: ["ignore", "ignore", "ignore"] });
              } catch {
                // ignore
              }
            }
          });
          stdout = `${stdout}\n\n[asv:msf] --- fallback run ---\n\n${rr2.stdout}`;
          stderr = `${stderr}\n\n[asv:msf] --- fallback run ---\n\n${rr2.stderr}`;
          exitCode = rr2.exitCode;
          await this.logEvent(runId, "fallback_action", run.created_by ?? null, null, null, {
            step: i + 1,
            from: "check",
            to: "run",
            reason: "check_not_supported",
            module: step.module
          });
        }

        combinedStdout.push(
          `\n\n[asv:msf] ===== step ${i + 1}/${stepsPlan.length} ${step.label} :: ${step.module} (${reqAction}${actAction !== reqAction ? `->${actAction}` : ""}) =====\n\n`
        );
        combinedStdout.push(stdout);
        combinedStderr.push(`\n\n[asv:msf] ===== step ${i + 1}/${stepsPlan.length} ${step.label} :: ${step.module} =====\n\n`);
        combinedStderr.push(stderr);

        const sum = summarizeMsfOutput({ action: actAction, module: step.module }, stdout, stderr);
        const stepRes: MsfStepResult = {
          step: i + 1,
          label: step.label,
          module: step.module,
          requestedAction: reqAction,
          actualAction: actAction,
          exitCode,
          verdict: sum.verdict,
          conclusion: sum.conclusion,
          highlights: sum.highlights,
          sessionsHint: sum.sessionsHint,
          lootHint: sum.lootHint
        };
        stepResults.push(stepRes);
        await this.logEvent(runId, "step_completed", run.created_by ?? null, null, null, stepRes);
      }

      await this.writeArtifact(runId, "msf.stdout", combinedStdout.join(""));
      await this.writeArtifact(runId, "msf.stderr", combinedStderr.join(""));

      const best = [...stepResults].sort((a, b) => verdictRank(b.verdict) - verdictRank(a.verdict))[0] ?? null;
      const ok = best ? best.verdict !== "error" : false;
      const status = ok ? "completed" : "failed";
      const summary = best
        ? `msf chain · verdict=${best.verdict} · best_step=${best.step}/${stepResults.length} · action=${best.actualAction} · module=${best.module}`
        : "msf chain · verdict=error · no_steps";

      await this.db.query(
        `UPDATE asv_msf_run
            SET status=$2, summary=$3, error=$4, ended_at=now(), updated_at=now()
          WHERE id=$1`,
        [runId, status, summary, ok ? null : capText((combinedStderr.join("") || combinedStdout.join("") || "msf failed").slice(0, 5000), 2000)]
      );
      await this.logEvent(runId, status, run.created_by ?? null, { status: "running" }, { status }, { best, steps: stepResults });

      await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
      this.ack(msg);
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e);
      try {
        await this.writeArtifact(runId, "msf.stderr", err);
      } catch {
        // ignore
      }
      await this.db.query(
        `UPDATE asv_msf_run
            SET status='failed', error=$2, ended_at=now(), updated_at=now()
          WHERE id=$1`,
        [runId, capText(err, 2000)]
      );
      await this.logEvent(runId, "failed", run.created_by ?? null, { status: "running" }, { status: "failed" }, { error: err });
      try {
        spawn("docker", ["rm", "-f", containerName], { stdio: ["ignore", "ignore", "ignore"] });
      } catch {
        // ignore
      }
      await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
      this.nack(msg, false);
    }
  }

  async onModuleDestroy() {
    try {
      await this.ch?.close();
    } finally {
      await this.conn?.close();
    }
  }
}


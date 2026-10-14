import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { access, mkdir, readdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { BadRequestException, Injectable, Logger, NotFoundException } from "@nestjs/common";

/** Last successful monthly-digest downloads kept per account. Older files are deleted. */
const MAX_DOWNLOADS = 5;

const MONTH_TITLE = [
  "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
  "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"
];

const USER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FILE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SAFE_PDF_NAME = /^[A-Za-z0-9._-]{1,120}\.pdf$/;

export type MonthlyDigestHistoryItem = {
  id: string;
  year: number;
  month: number;
  monthLabel: string;
  filename: string;
  downloadedAt: string;
};

const tails = new Map<string, Promise<void>>();

@Injectable()
export class MonthlyDigestHistoryService {
  private readonly logger = new Logger(MonthlyDigestHistoryService.name);

  async remember(
    userId: string,
    body: unknown,
    built: { buffer: Buffer; filename: string }
  ): Promise<void> {
    const period = readPeriod(body, built.filename);
    if (!period) throw new BadRequestException("Нужен календарный месяц");
    const folder = userFolder(userId);
    await withUserLock(folder, async () => {
      const dir = userDir(folder);
      await mkdir(dir, { recursive: true, mode: 0o700 });
      const id = randomUUID();
      const pdfPath = path.join(dir, `${id}.pdf`);
      await writeFile(pdfPath, built.buffer, { mode: 0o600 });
      try {
        const loaded = await readManifest(dir);
        const next = byNewest([
          {
            id,
            year: period.year,
            month: period.month,
            monthLabel: `${MONTH_TITLE[period.month - 1]} ${period.year}`,
            filename: safePdfName(built.filename, period.year, period.month),
            downloadedAt: nextDownloadedAt(loaded.items)
          },
          ...loaded.items
        ]).slice(0, MAX_DOWNLOADS);
        await writeManifest(dir, next);
        await sweep(dir, next);
      } catch (error) {
        await unlink(pdfPath).catch(() => undefined);
        throw error;
      }
    });
  }

  async list(userId: string): Promise<{ items: MonthlyDigestHistoryItem[] }> {
    const folder = userFolder(userId);
    return withUserLock(folder, async () => {
      const dir = userDir(folder);
      if (!existsSync(dir)) return { items: [] };
      const loaded = await readManifest(dir);
      if (loaded.broken) {
        this.logger.warn("monthly digest history manifest is unreadable; leaving files in place");
        return { items: [] };
      }
      const present: MonthlyDigestHistoryItem[] = [];
      for (const item of loaded.items) {
        try {
          await access(path.join(dir, `${item.id}.pdf`));
          present.push(item);
        } catch {
          // Missing file: drop the record on the rewrite below.
        }
      }
      const kept = byNewest(present).slice(0, MAX_DOWNLOADS);
      const same =
        kept.length === loaded.items.length && kept.every((item, index) => item.id === loaded.items[index]?.id);
      if (!same || (await hasStrayPdf(dir, kept))) {
        await writeManifest(dir, kept);
        await sweep(dir, kept);
      }
      return { items: kept };
    });
  }

  async read(userId: string, id: string): Promise<{ buffer: Buffer; filename: string }> {
    const fileId = id.trim().toLowerCase();
    if (!FILE_ID.test(fileId)) throw new NotFoundException();
    const folder = userFolder(userId);
    return withUserLock(folder, async () => {
      const dir = userDir(folder);
      const loaded = await readManifest(dir);
      const item = byNewest(loaded.items).slice(0, MAX_DOWNLOADS).find((row) => row.id === fileId);
      if (!item) throw new NotFoundException();
      const pdfPath = path.resolve(dir, `${item.id}.pdf`);
      if (path.relative(dir, pdfPath).startsWith("..")) throw new NotFoundException();
      try {
        const buffer = await readFile(pdfPath);
        return { buffer, filename: item.filename };
      } catch {
        throw new NotFoundException();
      }
    });
  }
}

function historyRoot(): string {
  const override = process.env.MONTHLY_DIGEST_HISTORY_DIR?.trim();
  if (override) return path.resolve(override);
  return path.join(repoRoot(process.cwd()), "data", "monthly-digest-history");
}

function repoRoot(start: string): string {
  let dir = path.resolve(start);
  for (let i = 0; i < 8; i += 1) {
    if (existsSync(path.join(dir, "pnpm-workspace.yaml"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.resolve(start);
}

function userFolder(userId: string): string {
  const trimmed = userId.trim();
  if (!trimmed || trimmed.length > 200) throw new BadRequestException("Некорректный пользователь");
  if (USER_UUID.test(trimmed)) return trimmed.toLowerCase();
  return `u-${createHash("sha256").update(trimmed).digest("hex").slice(0, 32)}`;
}

function userDir(folder: string): string {
  const root = historyRoot();
  const dir = path.resolve(root, folder);
  const rel = path.relative(root, dir);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new BadRequestException("Некорректный пользователь");
  }
  return dir;
}

function readPeriod(body: unknown, filename: string): { year: number; month: number } | null {
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const raw = body as Record<string, unknown>;
    const year = raw.year;
    const month = raw.month;
    if (typeof year === "number" && typeof month === "number" && validMonth(year, month)) {
      return { year, month };
    }
  }
  const match = /(\d{4})-(\d{2})\.pdf$/i.exec(path.basename(filename));
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  return validMonth(year, month) ? { year, month } : null;
}

function validMonth(year: number, month: number): boolean {
  return Number.isInteger(year) && year >= 1999 && year <= 2100 && Number.isInteger(month) && month >= 1 && month <= 12;
}

function safePdfName(filename: string, year: number, month: number): string {
  const base = path.basename(filename);
  if (SAFE_PDF_NAME.test(base)) return base;
  return `vulncontrol-digest-${year}-${String(month).padStart(2, "0")}.pdf`;
}

function nextDownloadedAt(existing: MonthlyDigestHistoryItem[]): string {
  const now = Date.now();
  const latest = existing.reduce((max, item) => Math.max(max, Date.parse(item.downloadedAt) || 0), 0);
  return new Date(now > latest ? now : latest + 1).toISOString();
}

function byNewest(items: MonthlyDigestHistoryItem[]): MonthlyDigestHistoryItem[] {
  return [...items].sort((a, b) => Date.parse(b.downloadedAt) - Date.parse(a.downloadedAt));
}

async function readManifest(dir: string): Promise<{ items: MonthlyDigestHistoryItem[]; broken: boolean }> {
  try {
    const raw = await readFile(path.join(dir, "manifest.json"), "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return { items: [], broken: true };
    const items: MonthlyDigestHistoryItem[] = [];
    for (const row of parsed) {
      const item = parseItem(row);
      if (item) items.push(item);
    }
    return { items: byNewest(items), broken: false };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { items: [], broken: false };
    return { items: [], broken: true };
  }
}

function parseItem(raw: unknown): MonthlyDigestHistoryItem | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = typeof row.id === "string" ? row.id.trim().toLowerCase() : "";
  const year = row.year;
  const month = row.month;
  const monthLabel = typeof row.monthLabel === "string" ? row.monthLabel.trim() : "";
  const filename = typeof row.filename === "string" ? row.filename.trim() : "";
  const downloadedAt = typeof row.downloadedAt === "string" ? row.downloadedAt : "";
  if (!FILE_ID.test(id) || typeof year !== "number" || typeof month !== "number" || !validMonth(year, month)) return null;
  if (!monthLabel || monthLabel.length > 40 || !SAFE_PDF_NAME.test(filename)) return null;
  if (Number.isNaN(Date.parse(downloadedAt))) return null;
  return { id, year, month, monthLabel, filename, downloadedAt };
}

async function writeManifest(dir: string, items: MonthlyDigestHistoryItem[]): Promise<void> {
  const tmp = path.join(dir, `.manifest-${randomUUID()}.tmp`);
  await writeFile(tmp, JSON.stringify(items), { mode: 0o600 });
  try {
    await rename(tmp, path.join(dir, "manifest.json"));
  } catch (error) {
    await unlink(tmp).catch(() => undefined);
    throw error;
  }
}

async function sweep(dir: string, kept: MonthlyDigestHistoryItem[]): Promise<void> {
  const ids = new Set(kept.map((item) => item.id));
  let names: string[] = [];
  try {
    names = await readdir(dir);
  } catch {
    return;
  }
  await Promise.all(
    names.map(async (name) => {
      if (name.startsWith(".manifest-") && name.endsWith(".tmp")) {
        await unlink(path.join(dir, name)).catch(() => undefined);
        return;
      }
      if (!name.endsWith(".pdf")) return;
      const id = name.slice(0, -4);
      if (!ids.has(id)) await unlink(path.join(dir, name)).catch(() => undefined);
    })
  );
}

async function hasStrayPdf(dir: string, kept: MonthlyDigestHistoryItem[]): Promise<boolean> {
  let names: string[] = [];
  try {
    names = await readdir(dir);
  } catch {
    return false;
  }
  const ids = new Set(kept.map((item) => item.id));
  return names.some((name) => name.endsWith(".pdf") && !ids.has(name.slice(0, -4)));
}

function withUserLock<T>(folder: string, fn: () => Promise<T>): Promise<T> {
  const prev = tails.get(folder) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  const tail = run.then(
    () => undefined,
    () => undefined
  );
  tails.set(folder, tail);
  void tail.finally(() => {
    if (tails.get(folder) === tail) tails.delete(folder);
  });
  return run;
}

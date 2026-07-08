import { createHash } from "node:crypto";

export const NVD_CATALOG_SETTINGS_KEY = "nvd_catalog";
/** Единственный режим: от текущего дня вглубь к 1999. */
export const NVD_CATALOG_SCAN_MODE = "newest_first" as const;
/** Нижняя граница каталога (самые старые CVE). */
export const NVD_CATALOG_START_ISO = "1999-01-01T00:00:00.000Z";
export const NVD_CATALOG_FLOOR_ISO = NVD_CATALOG_START_ISO;
/** NVD 2.0: pubStartDate/pubEndDate range must be ≤ 120 consecutive days. */
export const NVD_PUB_MAX_WINDOW_DAYS = 120;

export type NvdCatalogStatus = "pending" | "running" | "complete";
export type NvdCatalogScanMode = typeof NVD_CATALOG_SCAN_MODE;

export type NvdCatalogDoc = {
  status: NvdCatalogStatus;
  /** Нижняя граница deep-scan (от now() идём вниз). В pending до первого окна ≈ now(). */
  pubCursor: string;
  scanMode: NvdCatalogScanMode;
  requestedAt?: string;
  startedAt?: string;
  completedAt?: string;
  keyFingerprint?: string;
  totalUpserted?: number;
  /** @deprecated */
  lastWindowEnd?: string;
  lastWindowStart?: string;
};

export function fingerprintNvdApiKey(key: string): string {
  return createHash("sha256").update(key.trim()).digest("hex").slice(0, 16);
}

/** Верхняя граница каталога — всегда «сейчас». */
export function catalogScanHeadIso(now = new Date()): string {
  return now.toISOString();
}

/** Старт deep-scan: с текущего дня. */
export function initialReverseCatalogCursor(now = new Date()): string {
  return catalogScanHeadIso(now);
}

export function defaultNvdCatalogDoc(overrides?: Partial<NvdCatalogDoc>): NvdCatalogDoc {
  const nowIso = catalogScanHeadIso();
  return {
    status: "pending",
    scanMode: NVD_CATALOG_SCAN_MODE,
    pubCursor: nowIso,
    totalUpserted: 0,
    ...overrides
  };
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return Boolean(x) && typeof x === "object" && !Array.isArray(x);
}

export function parseNvdCatalogDoc(raw: unknown): NvdCatalogDoc | null {
  if (!isRecord(raw)) return null;
  const status = raw.status;
  if (status !== "pending" && status !== "running" && status !== "complete") return null;
  const pubCursor =
    typeof raw.pubCursor === "string" && raw.pubCursor.trim()
      ? raw.pubCursor.trim()
      : catalogScanHeadIso();
  const totalUpserted =
    typeof raw.totalUpserted === "number"
      ? raw.totalUpserted
      : Number.isFinite(Number(raw.totalUpserted))
        ? Number(raw.totalUpserted)
        : 0;
  return {
    status,
    pubCursor,
    scanMode: NVD_CATALOG_SCAN_MODE,
    requestedAt: typeof raw.requestedAt === "string" ? raw.requestedAt : undefined,
    startedAt: typeof raw.startedAt === "string" ? raw.startedAt : undefined,
    completedAt: typeof raw.completedAt === "string" ? raw.completedAt : undefined,
    keyFingerprint: typeof raw.keyFingerprint === "string" ? raw.keyFingerprint : undefined,
    totalUpserted,
    lastWindowEnd: typeof raw.lastWindowEnd === "string" ? raw.lastWindowEnd : undefined,
    lastWindowStart: typeof raw.lastWindowStart === "string" ? raw.lastWindowStart : undefined
  };
}

export function catalogBackfillActive(doc: NvdCatalogDoc | null | undefined): boolean {
  return doc != null && (doc.status === "pending" || doc.status === "running");
}

/** Всегда newest_first + pending/restart с текущего дня. */
export function normalizeNvdCatalogDoc(
  doc: NvdCatalogDoc | null | undefined,
  opts?: { forceRestart?: boolean; now?: Date }
): NvdCatalogDoc {
  const now = opts?.now ?? new Date();
  const nowIso = catalogScanHeadIso(now);
  const floorMs = new Date(NVD_CATALOG_FLOOR_ISO).getTime();

  if (!doc || opts?.forceRestart) {
    return defaultNvdCatalogDoc({
      status: "pending",
      pubCursor: nowIso,
      requestedAt: nowIso
    });
  }

  if (doc.status === "complete") {
    return { ...doc, scanMode: NVD_CATALOG_SCAN_MODE };
  }

  const legacyForward =
    rawScanMode(doc) === "oldest_first" ||
    (doc.status === "running" && isLikelyForwardCursor(doc.pubCursor, now));

  if (legacyForward) {
    return {
      ...doc,
      scanMode: NVD_CATALOG_SCAN_MODE,
      status: "pending",
      pubCursor: nowIso,
      completedAt: undefined,
      lastWindowEnd: undefined,
      lastWindowStart: undefined
    };
  }

  const curMs = new Date(doc.pubCursor).getTime();
  if (Number.isNaN(curMs) || curMs > now.getTime() + 60_000) {
    return {
      ...doc,
      scanMode: NVD_CATALOG_SCAN_MODE,
      pubCursor: nowIso,
      status: doc.status === "running" ? "running" : "pending"
    };
  }

  if (doc.status === "pending") {
    return { ...doc, scanMode: NVD_CATALOG_SCAN_MODE, pubCursor: nowIso };
  }

  if (curMs <= floorMs) {
    return { ...doc, scanMode: NVD_CATALOG_SCAN_MODE, pubCursor: NVD_CATALOG_FLOOR_ISO };
  }

  return { ...doc, scanMode: NVD_CATALOG_SCAN_MODE };
}

function rawScanMode(doc: NvdCatalogDoc): string | undefined {
  return (doc as NvdCatalogDoc & { scanMode?: string }).scanMode;
}

/** Forward-scan курсор часто «застревал» в 1999–2010 при уже загруженных свежих CVE. */
function isLikelyForwardCursor(pubCursor: string, now: Date): boolean {
  const curMs = new Date(pubCursor).getTime();
  if (Number.isNaN(curMs)) return true;
  const year = new Date(curMs).getUTCFullYear();
  return year < 2010 && now.getUTCFullYear() - year > 5;
}

/** Верх deep-scan: pending — с today, running — с сохранённого backEdge. */
export function resolveCatalogDeepEndMs(
  doc: NvdCatalogDoc,
  now = new Date()
): number {
  const nowMs = now.getTime();
  if (doc.status === "pending") return nowMs;
  const backMs = new Date(doc.pubCursor).getTime();
  if (Number.isNaN(backMs) || backMs > nowMs + 60_000) return nowMs;
  return backMs;
}

export function catalogReverseFloorReached(pubCursor: string): boolean {
  const curMs = new Date(pubCursor).getTime();
  const floorMs = new Date(NVD_CATALOG_FLOOR_ISO).getTime();
  return !Number.isNaN(curMs) && curMs <= floorMs;
}

/** 0 = только начали (backEdge≈now), 100 = дошли до 1999. */
export function catalogReverseProgressPct(pubCursor: string, now = new Date()): number {
  const floorMs = new Date(NVD_CATALOG_FLOOR_ISO).getTime();
  const nowMs = now.getTime();
  const curMs = new Date(pubCursor).getTime();
  if (Number.isNaN(curMs) || nowMs <= floorMs) return 0;
  if (curMs >= nowMs) return 0;
  if (curMs <= floorMs) return 100;
  return Math.round(((nowMs - curMs) / (nowMs - floorMs)) * 1000) / 10;
}

export type NvdCatalogTurboParams = {
  turbo: boolean;
  windowDays: number;
  windowsPerBurst: number;
  burstPauseMs: number;
  pageSleepMs: number;
  resultsPerPage: number;
};

/** Агрессивный режим: ~50 req/30s с ключом NVD → полный каталог за ~5–15 мин. */
export function resolveNvdCatalogTurboParams(opts: {
  turboEnabled: boolean;
  hasEffectiveApiKey: boolean;
}): NvdCatalogTurboParams {
  const turbo = opts.turboEnabled && opts.hasEffectiveApiKey;
  if (turbo) {
    return {
      turbo: true,
      windowDays: NVD_PUB_MAX_WINDOW_DAYS,
      windowsPerBurst: 60,
      burstPauseMs: 0,
      pageSleepMs: 620,
      resultsPerPage: 2000
    };
  }
  return {
    turbo: false,
    windowDays: 30,
    windowsPerBurst: 8,
    burstPauseMs: 500,
    pageSleepMs: 6000,
    resultsPerPage: 2000
  };
}

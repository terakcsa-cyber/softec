import fs from "node:fs/promises";
import { gunzipSync } from "node:zlib";
import { Agent, fetch as undiciFetch } from "undici";
import yauzl from "yauzl";
import {
  bduKeepStagingOnDisk,
  ensureBduStagingDir,
  pruneBduStaging,
  stagingArtifactName,
  writeStreamToStagingFile
} from "./staging.js";

/** Официальная полная выгрузка (обновляется на bdu.fstec.ru, внутри export/vulxml.xml). */
export const BDU_FSTEC_VULXML_ZIP_URL = "https://bdu.fstec.ru/files/documents/vulxml.zip";

/** Устаревший путь (часто 404); оставлен для явного override. */
export const BDU_FSTEC_VULXML_XML_URL = "https://bdu.fstec.ru/files/documents/vulxml.xml";

/** Зеркало GitHub — только fallback, снимок может отставать на недели. */
export const BDU_MIRROR_VULXML_GZ_URL =
  "https://github.com/velvetway/bdu-fstec-mirror/raw/main/data/vulxml.xml.gz";

export function resolveBduVulxmlUrl(): string {
  const explicit = process.env.BDU_XML_URL?.trim();
  if (explicit) return explicit;
  return BDU_FSTEC_VULXML_ZIP_URL;
}

export function resolveBduVulxmlFallbackUrl(): string | null {
  const v = process.env.BDU_XML_FALLBACK_URL?.trim();
  if (v) return v;
  const mirror = process.env.BDU_ALLOW_MIRROR_FALLBACK?.trim().toLowerCase();
  if (mirror === "true" || mirror === "1") return BDU_MIRROR_VULXML_GZ_URL;
  return null;
}

function bduFetchDispatcher(): Agent | undefined {
  if (process.env.BDU_TLS_INSECURE === "true" || process.env.BDU_TLS_INSECURE === "1") {
    return new Agent({ connect: { rejectUnauthorized: false } });
  }
  return undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function bduHttpGetToFile(url: string, destPath: string, timeoutMs: number): Promise<void> {
  const dispatcher = bduFetchDispatcher();
  const maxAttempts = Math.max(1, Math.min(8, Number(process.env.BDU_FETCH_MAX_ATTEMPTS ?? 4)));
  const perAttemptTimeoutMs = Math.max(60_000, timeoutMs);
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await undiciFetch(url, {
        dispatcher,
        headers: {
          accept: "application/zip, application/gzip, application/xml, text/xml, */*",
          "user-agent":
            process.env.BDU_FETCH_USER_AGENT?.trim() ||
            "Mozilla/5.0 (compatible; vuln-intel-ingest/1.0; +https://bdu.fstec.ru)"
        },
        signal: AbortSignal.timeout(perAttemptTimeoutMs)
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`BDU fetch failed ${res.status} ${res.statusText} ${text.slice(0, 200)}`);
      }
      await writeStreamToStagingFile(res.body, destPath);
      return;
    } catch (err) {
      lastError = err;
      await fs.rm(destPath, { force: true }).catch(() => undefined);
      if (attempt < maxAttempts) {
        const delayMs = Math.min(15_000, 2000 * attempt);
        // eslint-disable-next-line no-console
        console.warn(
          `[bdu-fetch] attempt ${attempt}/${maxAttempts} failed for ${url}: ${err instanceof Error ? err.message : String(err)}`
        );
        await sleep(delayMs);
      }
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error(`BDU fetch failed after ${maxAttempts} attempts: ${String(lastError)}`);
}

function extractVulxmlFromZipFile(zipPath: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) {
        reject(err ?? new Error("Failed to open BDU zip"));
        return;
      }
      const targets = ["export/vulxml.xml", "export/export.xml"];
      let found = false;

      zipfile.readEntry();
      zipfile.on("entry", (entry) => {
        const name = entry.fileName.replace(/\\/g, "/");
        if (targets.includes(name) || name.endsWith("/vulxml.xml")) {
          found = true;
          zipfile.openReadStream(entry, (err2, readStream) => {
            if (err2 || !readStream) {
              reject(err2 ?? new Error(`Cannot read zip entry ${name}`));
              return;
            }
            const chunks: Buffer[] = [];
            readStream.on("data", (c: Buffer) => chunks.push(c));
            readStream.on("end", () => {
              zipfile.close();
              resolve(Buffer.concat(chunks));
            });
            readStream.on("error", reject);
          });
          return;
        }
        zipfile.readEntry();
      });

      zipfile.on("end", () => {
        if (!found) reject(new Error("vulxml.xml not found inside BDU zip"));
      });
      zipfile.on("error", reject);
    });
  });
}

async function vulxmlFromStagingFile(artifactPath: string, url: string): Promise<Buffer> {
  const lower = url.toLowerCase();
  const head = await fs.readFile(artifactPath, { flag: "r" }).then((b) => b.subarray(0, 4));

  if (lower.endsWith(".zip") || (head[0] === 0x50 && head[1] === 0x4b)) {
    return extractVulxmlFromZipFile(artifactPath);
  }
  const raw = await fs.readFile(artifactPath);
  if (lower.endsWith(".gz") || (raw[0] === 0x1f && raw[1] === 0x8b)) {
    return gunzipSync(raw);
  }
  return raw;
}

/** Скачивает выгрузку БДУ во временный каталог, парсит vulxml.xml, затем удаляет артефакты. */
export async function fetchBduVulxmlBytes(url: string, timeoutMs: number): Promise<Buffer> {
  const stagingDir = await ensureBduStagingDir();
  await pruneBduStaging(stagingDir);
  const artifactPath = `${stagingDir}/${stagingArtifactName(url)}`;

  try {
    await bduHttpGetToFile(url, artifactPath, timeoutMs);
    const xml = await vulxmlFromStagingFile(artifactPath, url);
    return xml;
  } finally {
    if (!bduKeepStagingOnDisk()) {
      await pruneBduStaging(stagingDir);
    }
  }
}

/** Проверка доступности источника (Range/HEAD, без полной загрузки ZIP). */
export async function probeBduSourceReachability(timeoutMs = 8000): Promise<{
  ok: boolean;
  url: string;
  ms: number;
  status: number | null;
  error: string | null;
  tlsInsecure: boolean;
}> {
  const url = resolveBduVulxmlUrl();
  const dispatcher = bduFetchDispatcher();
  const tlsInsecure = Boolean(dispatcher);
  const headers = {
    accept: "application/zip, application/gzip, application/xml, text/xml, */*",
    "user-agent":
      process.env.BDU_FETCH_USER_AGENT?.trim() ||
      "Mozilla/5.0 (compatible; vuln-intel-platform/1.0; +https://bdu.fstec.ru)",
    range: "bytes=0-0"
  };
  const started = Date.now();
  try {
    let res = await undiciFetch(url, {
      method: "HEAD",
      dispatcher,
      headers,
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (res.status === 405 || res.status === 501) {
      res = await undiciFetch(url, {
        method: "GET",
        dispatcher,
        headers,
        signal: AbortSignal.timeout(timeoutMs)
      });
    }
    const ms = Date.now() - started;
    const ok = res.ok || res.status === 206;
    return {
      ok,
      url,
      ms,
      status: res.status,
      error: ok ? null : `HTTP ${res.status} ${res.statusText}`,
      tlsInsecure
    };
  } catch (e) {
    return {
      ok: false,
      url,
      ms: Date.now() - started,
      status: null,
      error: e instanceof Error ? e.message : String(e),
      tlsInsecure
    };
  }
}

/** Primary URL, при ошибке — optional fallback (зеркало). */
export async function fetchBduVulxmlWithFallback(timeoutMs: number): Promise<{
  xml: Buffer;
  sourceUrl: string;
  usedFallback: boolean;
}> {
  const primary = resolveBduVulxmlUrl();
  const fallback = resolveBduVulxmlFallbackUrl();
  const errors: unknown[] = [];

  try {
    const xml = await fetchBduVulxmlBytes(primary, timeoutMs);
    return { xml, sourceUrl: primary, usedFallback: false };
  } catch (primaryErr) {
    errors.push(primaryErr);
  }

  if (fallback) {
    try {
      const xml = await fetchBduVulxmlBytes(fallback, timeoutMs);
      return { xml, sourceUrl: fallback, usedFallback: true };
    } catch (fallbackErr) {
      errors.push(fallbackErr);
    }
  }

  const detail = errors
    .map((e) => (e instanceof Error ? e.message : String(e)))
    .join("; ");
  throw new Error(`BDU fetch failed (primary and fallback): ${detail}`);
}

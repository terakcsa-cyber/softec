import { createWriteStream } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";

/** Каталог для временной выгрузки БДУ (ZIP/GZ). После ingest содержимое удаляется. */
export function resolveBduStagingDir(): string {
  const explicit = process.env.BDU_STAGING_DIR?.trim();
  if (explicit) return path.resolve(explicit);
  return path.join(os.tmpdir(), "vuln-intel-bdu");
}

export function bduKeepStagingOnDisk(): boolean {
  const v = process.env.BDU_KEEP_STAGING?.trim().toLowerCase();
  return v === "true" || v === "1";
}

export async function ensureBduStagingDir(): Promise<string> {
  const dir = resolveBduStagingDir();
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

/** Удаляет предыдущие артефакты выгрузки перед новой партией. */
export async function pruneBduStaging(dir = resolveBduStagingDir()): Promise<void> {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    await Promise.all(
      entries.map(async (ent) => {
        const full = path.join(dir, ent.name);
        await fs.rm(full, { recursive: true, force: true });
      })
    );
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT") return;
    throw e;
  }
}

export function stagingArtifactName(url: string): string {
  const lower = url.toLowerCase();
  if (lower.endsWith(".zip")) return "vulxml-download.zip";
  if (lower.endsWith(".gz")) return "vulxml-download.xml.gz";
  if (lower.endsWith(".xml")) return "vulxml-download.xml";
  return "vulxml-download.bin";
}

export async function writeStreamToStagingFile(
  body: ReadableStream<Uint8Array> | null,
  destPath: string
): Promise<void> {
  if (!body) throw new Error("BDU fetch: empty response body");
  const nodeStream = Readable.fromWeb(body as import("node:stream/web").ReadableStream);
  await pipeline(nodeStream, createWriteStream(destPath));
}

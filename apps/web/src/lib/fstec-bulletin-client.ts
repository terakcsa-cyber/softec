/**
 * Клиентская загрузка бюллетеней — без `@vuln-intel/shared`: barrel тянет yauzl → fd-slicer → `fs`.
 */
import { strFromU8, unzipSync } from "fflate";

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

export function extractPlainTextFromDocx(buf: Uint8Array | ArrayBuffer): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const unzipped = unzipSync(bytes);
  const docEntry =
    unzipped["word/document.xml"] ??
    Object.entries(unzipped).find(([k]) => k.endsWith("word/document.xml"))?.[1];
  if (!docEntry) throw new Error("word/document.xml not found in docx");
  const xml = strFromU8(docEntry);
  const withBreaks = xml
    .replace(/<w:tab[^/]*\/>/gi, "\t")
    .replace(/<\/w:p>/gi, "\n")
    .replace(/<w:br[^/]*\/>/gi, "\n");
  const stripped = withBreaks.replace(/<[^>]+>/g, "");
  return decodeXmlEntities(stripped)
    .replace(/\r\n/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function guessBulletinReferenceFromFilename(name: string): string | null {
  const base = name.replace(/\.[^.]+$/, "").trim();
  if (!base) return null;
  const parts = base.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return parts.join(" ");
  return base;
}

export type FstecBulletinParsedItemClient = {
  ordinal: number;
  bduId: string;
  cvssLabel: string;
  headline: string;
  body: string;
  remediation: string | null;
  compensatingMeasures: string | null;
};

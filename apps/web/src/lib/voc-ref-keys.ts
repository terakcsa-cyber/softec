import type { VocSource } from "./voc-api";

export function cveRefKey(cveId: string): string {
  const id = cveId.trim().toUpperCase();
  return id.startsWith("CVE:") ? id : `CVE:${id}`;
}

export function bduRefKey(bduId: string): string {
  const id = bduId.trim();
  return id.startsWith("BDU:") ? id : `BDU:${id}`;
}

export function tgRefKey(postId: string): string {
  return postId.startsWith("TG:") ? postId : `TG:${postId}`;
}

export function parseVocRefKey(refKey: string): { source: VocSource; refId: string } | null {
  const k = refKey.trim();
  if (k.startsWith("CVE:")) return { source: "cve", refId: k.slice(4) };
  if (k.startsWith("BDU:")) return { source: "bdu", refId: k.slice(4) };
  if (k.startsWith("TG:")) return { source: "tg", refId: k.slice(3) };
  return null;
}

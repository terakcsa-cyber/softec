/** Снятые/готовые за эту вкладку — не возвращаются в «Сейчас» после live-poll. */
const closedRefKeys = new Set<string>();

export function markVocRefClosed(refKey: string) {
  const k = refKey.trim();
  if (k) closedRefKeys.add(k);
}

export function markVocRefOpen(refKey: string) {
  closedRefKeys.delete(refKey.trim());
}

export function isVocRefSessionClosed(refKey: string) {
  return closedRefKeys.has(refKey.trim());
}

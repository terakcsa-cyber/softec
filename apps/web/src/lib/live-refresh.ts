"use client";

import { useEffect, useState } from "react";

/** Интервал опроса, когда вкладка активна */
export const LIVE_POLL_MS = 12_000;

/** Интервал опроса, когда вкладка в фоне */
export const LIVE_POLL_BACKGROUND_MS = 90_000;

export function useLivePollInterval(
  activeMs: number = LIVE_POLL_MS,
  backgroundMs: number = LIVE_POLL_BACKGROUND_MS
): number {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const sync = () => setVisible(document.visibilityState === "visible");
    sync();
    document.addEventListener("visibilitychange", sync);
    return () => document.removeEventListener("visibilitychange", sync);
  }, []);

  return visible ? activeMs : backgroundMs;
}

/** Общие опции react-query для «живых» панелей */
export function useLiveQueryOptions(activeMs: number = LIVE_POLL_MS) {
  const refetchInterval = useLivePollInterval(activeMs);
  return {
    staleTime: 8_000,
    refetchInterval,
    refetchIntervalInBackground: false
  } as const;
}

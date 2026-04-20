"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from "react";

const STORAGE_KEY = "vip:theme";

export type Theme = "dark" | "light";

type ThemeContextValue = {
  theme: Theme;
  setTheme: (t: Theme) => void;
  /** false до гидрации — не анимируйте от темы */
  ready: boolean;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

function applyDomTheme(t: Theme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.remove("dark", "light");
  root.classList.add(t);
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("dark");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const t: Theme = raw === "light" || raw === "dark" ? raw : "dark";
      setThemeState(t);
      applyDomTheme(t);
    } catch {
      applyDomTheme("dark");
    }
    setReady(true);
  }, []);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      // ignore
    }
    applyDomTheme(t);
  }, []);

  const value = useMemo(
    () => ({ theme, setTheme, ready }),
    [theme, setTheme, ready]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}

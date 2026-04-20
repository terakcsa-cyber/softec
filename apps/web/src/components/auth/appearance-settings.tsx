"use client";

import { useTheme } from "@/contexts/theme-context";
import { Moon, Sun } from "lucide-react";
import { cn } from "../ui/cn";

export function AppearanceSettings() {
  const { theme, setTheme } = useTheme();

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-border dark:bg-white/[0.04] dark:shadow-none">
      <div className="text-sm font-medium text-fg/90">Оформление</div>
      <p className="mt-1 text-xs text-muted">Тема интерфейса сохраняется в этом браузере.</p>

      <div className="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setTheme("dark")}
          className={cn(
            "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs font-medium transition",
            theme === "dark"
              ? "border-accent/40 bg-accent/15 text-fg/95"
              : "border-slate-200 bg-slate-50 text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-white/[0.06] dark:hover:bg-white/[0.09]"
          )}
        >
          <Moon className="h-3.5 w-3.5 opacity-90" aria-hidden />
          Тёмная
        </button>
        <button
          type="button"
          onClick={() => setTheme("light")}
          className={cn(
            "inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs font-medium transition",
            theme === "light"
              ? "border-accent/40 bg-accent/15 text-fg/95"
              : "border-slate-200 bg-slate-50 text-fg/80 hover:bg-slate-100 dark:border-border dark:bg-white/[0.06] dark:hover:bg-white/[0.09]"
          )}
        >
          <Sun className="h-3.5 w-3.5 opacity-90" aria-hidden />
          Светлая
        </button>
      </div>
    </div>
  );
}

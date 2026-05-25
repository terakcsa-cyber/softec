"use client";

import { useState } from "react";
import { FileText, Newspaper } from "lucide-react";
import { cn } from "../ui/cn";
import { FstecNewsPanel } from "./fstec-news-panel";
import { FstecBulletinsPanel } from "./fstec-bulletins-panel";

export type FstecModulePanelProps = {
  onOpenCve?: (cveId: string) => void;
  onOpenBdu?: (bduId: string) => void;
};

type Tab = "feed" | "bulletins";

export function FstecModulePanel({ onOpenCve, onOpenBdu }: FstecModulePanelProps) {
  const [tab, setTab] = useState<Tab>("bulletins");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setTab("bulletins")}
          className={cn(
            "inline-flex items-center gap-2 rounded-xl px-3 py-2 text-xs font-medium transition",
            tab === "bulletins"
              ? "bg-accent text-bg"
              : "bg-fg/5 text-fg/70 hover:bg-fg/10"
          )}
        >
          <FileText className="h-4 w-4" />
          Бюллетени
        </button>
        <button
          type="button"
          onClick={() => setTab("feed")}
          className={cn(
            "inline-flex items-center gap-2 rounded-xl px-3 py-2 text-xs font-medium transition",
            tab === "feed"
              ? "bg-accent text-bg"
              : "bg-fg/5 text-fg/70 hover:bg-fg/10"
          )}
        >
          <Newspaper className="h-4 w-4" />
          Лента
        </button>
      </div>

      {tab === "bulletins" ? (
        <FstecBulletinsPanel onOpenBdu={onOpenBdu} />
      ) : (
        <div className="glass rounded-2xl p-5 sm:p-6">
          <FstecNewsPanel onOpenCve={onOpenCve} onOpenBdu={onOpenBdu} />
        </div>
      )}
    </div>
  );
}

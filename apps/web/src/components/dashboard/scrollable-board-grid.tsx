"use client";

import type { ReactNode } from "react";
import { cn } from "../ui/cn";

export function ScrollableBoardGrid({
  children,
  className,
  maxHeightClass = "max-h-[min(28rem,calc(100vh-18rem))]",
  empty
}: {
  children: ReactNode;
  className?: string;
  maxHeightClass?: string;
  empty?: ReactNode;
}) {
  const hasChildren = Boolean(children);

  if (!hasChildren && empty) {
    return <>{empty}</>;
  }

  return (
    <div className={cn("relative", className)}>
      <div
        className={cn(
          "overflow-y-auto overscroll-contain pr-1",
          maxHeightClass,
          "[scrollbar-width:thin] [scrollbar-color:rgba(148,163,184,0.45)_transparent]",
          "[&::-webkit-scrollbar]:w-1.5",
          "[&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-slate-300/80",
          "dark:[&::-webkit-scrollbar-thumb]:bg-white/15"
        )}
      >
        {children}
      </div>
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-slate-50/95 to-transparent dark:from-black/40"
      />
    </div>
  );
}

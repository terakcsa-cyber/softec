"use client";

import { animate, motion, useMotionValue } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import { cn } from "./cn";

function formatNum(v: number, fractionDigits: number) {
  if (!Number.isFinite(v)) return "—";
  if (fractionDigits > 0) return v.toFixed(fractionDigits);
  return Math.round(v).toLocaleString();
}

type LiveNumberProps = {
  value: number;
  className?: string;
  fractionDigits?: number;
  suffix?: string;
};

export function LiveNumber({ value, className, fractionDigits = 0, suffix = "" }: LiveNumberProps) {
  const motionVal = useMotionValue(value);
  const [text, setText] = useState(() => formatNum(value, fractionDigits));
  const prev = useRef(value);
  const [flash, setFlash] = useState<"up" | "down" | null>(null);

  useEffect(() => {
    const ctrl = animate(motionVal, value, {
      type: "spring",
      stiffness: 120,
      damping: 22,
      onUpdate: (v) => setText(formatNum(v, fractionDigits))
    });

    if (value !== prev.current) {
      setFlash(value > prev.current ? "up" : "down");
      prev.current = value;
      const t = window.setTimeout(() => setFlash(null), 650);
      return () => {
        ctrl.stop();
        window.clearTimeout(t);
      };
    }

    return () => ctrl.stop();
  }, [value, motionVal, fractionDigits]);

  return (
    <motion.span
      className={cn("inline-block tabular-nums", className)}
      animate={
        flash === "up"
          ? { scale: [1, 1.07, 1], color: ["inherit", "rgb(16, 185, 129)", "inherit"] }
          : flash === "down"
            ? { scale: [1, 1.04, 1], color: ["inherit", "rgb(245, 158, 11)", "inherit"] }
            : { scale: 1 }
      }
      transition={{ duration: 0.45, ease: "easeOut" }}
    >
      {text}
      {suffix}
    </motion.span>
  );
}

type LiveTextProps = {
  value: string;
  className?: string;
};

/** Строковые KPI с лёгким «пульсом» при смене значения */
export function LiveText({ value, className }: LiveTextProps) {
  const prev = useRef(value);
  const [flash, setFlash] = useState(false);

  useEffect(() => {
    if (value === prev.current) return;
    prev.current = value;
    setFlash(true);
    const t = window.setTimeout(() => setFlash(false), 550);
    return () => window.clearTimeout(t);
  }, [value]);

  return (
    <motion.span
      className={className}
      animate={flash ? { scale: [1, 1.05, 1] } : { scale: 1 }}
      transition={{ duration: 0.4 }}
    >
      {value}
    </motion.span>
  );
}

type LivePulseDotProps = {
  active?: boolean;
  className?: string;
};

export function LivePulseDot({ active, className }: LivePulseDotProps) {
  return (
    <span className={cn("relative inline-flex h-2 w-2", className)}>
      {active ? (
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sky-400/75 opacity-70" />
      ) : null}
      <span
        className={cn(
          "relative inline-flex h-2 w-2 rounded-full",
          active ? "bg-sky-500" : "bg-emerald-500"
        )}
      />
    </span>
  );
}

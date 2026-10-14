"use client";

import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type CSSProperties, type KeyboardEvent as ReactKeyboardEvent, type ReactNode, type RefObject } from "react";
import { createPortal } from "react-dom";
import { ChevronDown } from "lucide-react";
import { cn } from "@/components/ui/cn";

type Align = "start" | "end" | "after";
type WidthMode = number | "anchor" | "auto";

const MARGIN = 8;

export function viewportBox() {
  const vv = window.visualViewport;
  const left = vv?.offsetLeft ?? 0;
  const top = vv?.offsetTop ?? 0;
  const width = vv?.width ?? document.documentElement.clientWidth;
  const height = vv?.height ?? document.documentElement.clientHeight;
  return { left, top, right: left + width, bottom: top + height, width, height };
}

function clamp(value: number, min: number, max: number) {
  if (max < min) return min;
  return Math.min(Math.max(value, min), max);
}

/** Fixed menu anchored to a trigger. Width uses the layout viewport, not 100vw, so a classic Windows scrollbar does not shove the panel off-screen. */
export function useAnchoredStyle(
  open: boolean,
  anchorRef: RefObject<HTMLElement | null>,
  menuRef: RefObject<HTMLElement | null>,
  align: Align,
  widthMode: WidthMode,
  maxHeightCap: number,
  signature = ""
) {
  const [style, setStyle] = useState<CSSProperties>({
    position: "fixed",
    top: 0,
    left: 0,
    visibility: "hidden",
    zIndex: 80
  });

  const place = useCallback(() => {
    const anchor = anchorRef.current;
    const menu = menuRef.current;
    if (!anchor || !menu) return;
    const rect = anchor.getBoundingClientRect();
    const box = viewportBox();
    const previousWidth = menu.style.width;
    menu.style.width = "max-content";
    const natural = menu.offsetWidth;
    menu.style.width = previousWidth;
    const cap = Math.max(96, box.width - MARGIN * 2);
    const width = widthMode === "anchor"
      ? Math.min(Math.max(rect.width, 0), cap)
      : widthMode === "auto"
        ? Math.min(Math.max(natural, rect.width, 160), cap)
        : Math.min(widthMode, cap);
    const gap = 4;
    const contentHeight = menu.scrollHeight;
    let left = align === "end" ? rect.right - width : align === "after" ? rect.right + gap : rect.left;
    if (align === "after" && left + width > box.right - MARGIN) left = rect.left - gap - width;
    left = clamp(left, box.left + MARGIN, box.right - MARGIN - width);
    const spaceBelow = box.bottom - (align === "after" ? rect.top : rect.bottom) - MARGIN - (align === "after" ? 0 : gap);
    const spaceAbove = (align === "after" ? rect.bottom : rect.top) - box.top - MARGIN - (align === "after" ? 0 : gap);
    const openBelow = spaceBelow >= Math.min(contentHeight, 160) || spaceBelow >= spaceAbove;
    const maxHeight = Math.max(96, Math.min(maxHeightCap, openBelow ? spaceBelow : spaceAbove));
    const height = Math.min(contentHeight, maxHeight);
    let top = align === "after"
      ? (openBelow ? rect.top : rect.bottom - height)
      : openBelow ? rect.bottom + gap : rect.top - gap - height;
    top = clamp(top, box.top + MARGIN, box.bottom - MARGIN - height);
    setStyle({
      position: "fixed",
      top,
      left,
      width,
      maxHeight,
      zIndex: 80,
      visibility: "visible"
    });
  }, [align, anchorRef, maxHeightCap, menuRef, widthMode]);

  useLayoutEffect(() => {
    if (!open) return;
    place();
    const onScroll = () => place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", onScroll, true);
    const vv = window.visualViewport;
    vv?.addEventListener("resize", place);
    vv?.addEventListener("scroll", place);
    return () => {
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", onScroll, true);
      vv?.removeEventListener("resize", place);
      vv?.removeEventListener("scroll", place);
    };
  }, [open, place, signature]);

  return style;
}

/** Close on an outside press without swallowing the item click. Pointerdown inside the menu or trigger is ignored, so the following click still activates the row on Windows. */
export function useOutsideClose(open: boolean, refs: Array<RefObject<HTMLElement | null>>, onClose: () => void) {
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const refsRef = useRef(refs);
  refsRef.current = refs;
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (refsRef.current.some((ref) => ref.current?.contains(target))) return;
      closeRef.current();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeRef.current();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
}

export function useClampedPoint(x: number, y: number, menuRef: RefObject<HTMLElement | null>, width = 176) {
  const [style, setStyle] = useState<CSSProperties>({
    position: "fixed",
    top: y,
    left: x,
    width,
    visibility: "hidden",
    zIndex: 80
  });
  useLayoutEffect(() => {
    const menu = menuRef.current;
    const box = viewportBox();
    const w = Math.min(width, Math.max(96, box.width - MARGIN * 2));
    const contentHeight = menu?.scrollHeight ?? 0;
    let left = x;
    if (left + w > box.right - MARGIN) left = box.right - MARGIN - w;
    left = Math.max(box.left + MARGIN, left);
    let top = y;
    const roomBelow = box.bottom - MARGIN - top;
    if (contentHeight > roomBelow && top - contentHeight > box.top + MARGIN) {
      top = Math.max(box.top + MARGIN, box.bottom - MARGIN - Math.min(contentHeight, box.height - MARGIN * 2));
    }
    const maxHeight = Math.max(96, box.bottom - MARGIN - top);
    setStyle({
      position: "fixed",
      top,
      left,
      width: w,
      maxHeight,
      visibility: "visible",
      zIndex: 80
    });
  }, [menuRef, width, x, y]);
  return style;
}

export function VcDrop({
  open,
  anchorRef,
  onClose,
  align = "start",
  width = "auto",
  maxHeight = 320,
  className,
  children,
  signature = "",
  portal = false
}: {
  open: boolean;
  anchorRef: RefObject<HTMLElement | null>;
  onClose: () => void;
  align?: Align;
  width?: WidthMode;
  maxHeight?: number;
  className?: string;
  children: ReactNode;
  signature?: string;
  portal?: boolean;
}) {
  const menuRef = useRef<HTMLDivElement>(null);
  const style = useAnchoredStyle(open, anchorRef, menuRef, align, width, maxHeight, signature);
  useOutsideClose(open, [anchorRef, menuRef], onClose);
  if (!open) return null;
  const menu = (
    <div
      ref={menuRef}
      className={cn(
        "vc-pop overflow-x-hidden overflow-y-auto rounded-lg border border-[var(--vc-border)] bg-[var(--vc-surface)] text-[var(--vc-text)] shadow-xl",
        portal && "vc-shell",
        className
      )}
      style={style}
    >
      {children}
    </div>
  );
  if (portal && typeof document !== "undefined") return createPortal(menu, document.body);
  return menu;
}

export const vcMenuItem =
  "block w-full min-w-0 truncate rounded px-2 py-1.5 text-left text-[12px] leading-snug text-[var(--vc-text)] hover:bg-[var(--vc-hover)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--vc-primary)]";

export function VcSelect({
  value,
  onChange,
  options,
  ariaLabel,
  className,
  align = "start"
}: {
  value: string;
  onChange: (value: string) => void;
  options: Array<[string, string]>;
  ariaLabel?: string;
  className?: string;
  align?: Align;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const anchorRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const listId = useId();
  const style = useAnchoredStyle(open, anchorRef, menuRef, align, "auto", 320);
  useOutsideClose(open, [anchorRef, menuRef], () => setOpen(false));
  const selectedIndex = Math.max(0, options.findIndex(([id]) => id === value));
  const label = options[selectedIndex]?.[1] ?? options.find(([id]) => id === value)?.[1] ?? "";

  useEffect(() => {
    if (!open) return;
    const node = menuRef.current?.querySelector<HTMLElement>("[data-active='true']");
    node?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  function pick(id: string) {
    onChange(id);
    setOpen(false);
    anchorRef.current?.focus();
  }

  function onKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>) {
    if (!open) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp" || event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setActive(selectedIndex);
        setOpen(true);
      }
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((index) => Math.min(options.length - 1, index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((index) => Math.max(0, index - 1));
    } else if (event.key === "Home") {
      event.preventDefault();
      setActive(0);
    } else if (event.key === "End") {
      event.preventDefault();
      setActive(Math.max(0, options.length - 1));
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      const next = options[active];
      if (next) pick(next[0]);
    } else if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
    }
  }

  return (
    <>
      <button
        ref={anchorRef}
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listId}
        onClick={() => {
          setActive(selectedIndex);
          setOpen((current) => !current);
        }}
        onKeyDown={onKeyDown}
        className={cn(
          "inline-flex h-8 min-w-0 max-w-full items-center justify-between gap-2 rounded-lg border border-[var(--vc-border)] bg-[var(--vc-inset-2)] px-2.5 text-left text-[12px] leading-none text-[var(--vc-text)] outline-none hover:border-[var(--vc-hover-border)]",
          className
        )}
      >
        <span className="min-w-0 flex-1 truncate">{label}</span>
        <ChevronDown className="h-3.5 w-3.5 shrink-0 text-[var(--vc-muted)]" aria-hidden />
      </button>
      {open ? (
        <div
          ref={menuRef}
          id={listId}
          role="listbox"
          aria-label={ariaLabel}
          className="vc-pop overflow-x-hidden overflow-y-auto rounded-lg border border-[var(--vc-border)] bg-[var(--vc-surface)] py-1 shadow-xl"
          style={style}
        >
          {options.map(([id, text], index) => {
            const on = index === active;
            const chosen = id === value;
            return (
              <button
                key={id}
                type="button"
                role="option"
                aria-selected={chosen}
                data-active={on ? "true" : "false"}
                title={text}
                onMouseEnter={() => setActive(index)}
                onClick={() => pick(id)}
                className={cn(vcMenuItem, "mx-1 w-max max-w-[calc(100%-0.5rem)]", on && "bg-[var(--vc-hover)]", chosen && "font-medium")}
              >
                {text}
              </button>
            );
          })}
        </div>
      ) : null}
    </>
  );
}

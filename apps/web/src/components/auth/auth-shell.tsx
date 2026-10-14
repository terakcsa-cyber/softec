"use client";

import { Shield } from "lucide-react";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";

const fieldClass =
  "mt-1.5 w-full rounded-lg border border-[var(--vc-border)] bg-[var(--vc-well)] px-3 py-2.5 text-[13px] text-[var(--vc-text)] outline-none transition placeholder:text-[var(--vc-muted)] focus:border-[color-mix(in_srgb,var(--vc-primary)_55%,transparent)] focus:ring-2 focus:ring-[color-mix(in_srgb,var(--vc-primary)_25%,transparent)]";

const labelClass = "block text-[11px] font-medium uppercase tracking-wide text-[var(--vc-muted)]";

const primaryBtnClass =
  "inline-flex h-10 flex-1 items-center justify-center rounded-lg bg-[#2f6bff] px-4 text-[13px] font-medium text-white shadow-[0_0_20px_rgba(47,107,255,0.35)] transition hover:bg-[#3b76ff] disabled:cursor-not-allowed disabled:opacity-50";

const secondaryBtnClass =
  "inline-flex h-10 items-center justify-center rounded-lg border border-[var(--vc-border)] bg-transparent px-4 text-[13px] text-[var(--vc-text)] transition hover:bg-[var(--vc-hover)]";

export function AuthField({
  label,
  children,
  hint
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <div>
      <label className={labelClass}>{label}</label>
      {children}
      {hint ? <p className="mt-1.5 text-[11px] leading-4 text-[var(--vc-muted)]">{hint}</p> : null}
    </div>
  );
}

export function AuthInput(props: InputHTMLAttributes<HTMLInputElement>) {
  const { className, ...rest } = props;
  return <input {...rest} className={[fieldClass, className].filter(Boolean).join(" ")} />;
}

export function AuthError({ children }: { children: ReactNode }) {
  return (
    <div
      className="rounded-lg border px-3 py-2 text-[13px]"
      style={{
        borderColor: "color-mix(in srgb, var(--vc-critical) 40%, transparent)",
        background: "color-mix(in srgb, var(--vc-critical) 12%, transparent)",
        color: "var(--vc-critical-text)"
      }}
    >
      {children}
    </div>
  );
}

export function AuthSuccess({ children }: { children: ReactNode }) {
  return (
    <div
      className="rounded-lg border px-3 py-2 text-[13px]"
      style={{
        borderColor: "color-mix(in srgb, var(--vc-success) 40%, transparent)",
        background: "color-mix(in srgb, var(--vc-success) 12%, transparent)",
        color: "var(--vc-success-text)"
      }}
    >
      {children}
    </div>
  );
}

export function AuthPrimaryButton({
  children,
  className,
  type = "submit",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type={type} {...props} className={[primaryBtnClass, className].filter(Boolean).join(" ")}>
      {children}
    </button>
  );
}

export function AuthSecondaryButton({
  children,
  className,
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type={type} {...props} className={[secondaryBtnClass, className].filter(Boolean).join(" ")}>
      {children}
    </button>
  );
}

export function AuthShell({
  title,
  subtitle,
  children,
  footer
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div
      className="vc-shell relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-10 text-[13px] text-[var(--vc-text)]"
      style={{ background: "var(--vc-bg)" }}
    >
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(900px 480px at 50% -10%, rgba(47,107,255,0.28), transparent 60%), radial-gradient(700px 420px at 85% 110%, rgba(29,78,216,0.18), transparent 55%)"
        }}
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            "linear-gradient(var(--vc-grid) 1px, transparent 1px), linear-gradient(90deg, var(--vc-grid) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
          maskImage: "radial-gradient(ellipse at center, black 20%, transparent 75%)"
        }}
      />

      <div className="relative w-full max-w-[420px]">
        <div className="mb-6 flex items-center gap-3">
          <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-[#2f6bff] text-white shadow-[0_0_22px_rgba(47,107,255,0.45)]">
            <Shield className="h-5 w-5" />
          </span>
          <div className="min-w-0">
            <div className="text-[16px] font-semibold leading-none tracking-tight">VulnControl</div>
            <div className="mt-1.5 text-[11px] leading-tight text-[var(--vc-muted)]">
              Vulnerability Management Platform
            </div>
          </div>
        </div>

        <div className="rounded-2xl border border-[var(--vc-border)] bg-[var(--vc-surface)] p-7 shadow-[0_24px_80px_rgba(0,0,0,0.35)]">
          <h1 className="text-[18px] font-semibold tracking-tight text-[var(--vc-text)]">{title}</h1>
          <p className="mt-2 text-[13px] leading-5 text-[var(--vc-muted)]">{subtitle}</p>
          <div className="mt-6">{children}</div>
        </div>

        {footer ? <div className="mt-4 text-center text-[11px] text-[var(--vc-muted)]">{footer}</div> : null}
      </div>
    </div>
  );
}

export function AuthLoading({ message }: { message: string }) {
  return (
    <div
      className="vc-shell flex min-h-screen flex-col items-center justify-center gap-3 text-[13px] text-[var(--vc-muted)]"
      style={{ background: "var(--vc-bg)" }}
    >
      <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#2f6bff] text-white shadow-[0_0_18px_rgba(47,107,255,0.4)]">
        <Shield className="h-4 w-4" />
      </span>
      <span>{message}</span>
    </div>
  );
}

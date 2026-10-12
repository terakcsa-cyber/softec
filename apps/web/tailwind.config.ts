import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-sans)", "IBM Plex Sans", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "IBM Plex Mono", "ui-monospace", "monospace"]
      },
      borderRadius: {
        lg: "0.5rem",
        xl: "0.625rem",
        "2xl": "0.75rem"
      },
      colors: {
        bg: "hsl(var(--color-bg) / <alpha-value>)",
        fg: "hsl(var(--color-fg) / <alpha-value>)",
        muted: "hsl(var(--color-muted) / <alpha-value>)",
        card: "hsl(var(--color-card) / <alpha-value>)",
        border: "hsl(var(--color-border) / <alpha-value>)",
        accent: "hsl(var(--color-accent) / <alpha-value>)",
        danger: "hsl(var(--color-danger) / <alpha-value>)",
        warn: "hsl(var(--color-warn) / <alpha-value>)",
        ok: "hsl(var(--color-ok) / <alpha-value>)"
      },
      boxShadow: {
        glass: "0 0 0 1px hsl(0 0% 100% / 0.04)"
      },
      backdropBlur: {
        glass: "18px"
      }
    }
  },
  plugins: []
} satisfies Config;


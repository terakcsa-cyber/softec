import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "hsl(222 47% 5%)",
        fg: "hsl(210 40% 98%)",
        muted: "hsl(215 20% 65%)",
        card: "hsl(222 47% 8%)",
        border: "hsl(217 20% 18%)",
        accent: "hsl(252 95% 70%)",
        danger: "hsl(0 84% 60%)",
        warn: "hsl(38 92% 55%)",
        ok: "hsl(142 76% 45%)"
      },
      boxShadow: {
        glass: "0 0 0 1px hsl(0 0% 100% / 0.06), 0 10px 40px hsl(0 0% 0% / 0.35)"
      },
      backdropBlur: {
        glass: "18px"
      }
    }
  },
  plugins: []
} satisfies Config;


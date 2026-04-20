import "./globals.css";
import type { Metadata } from "next";
import Script from "next/script";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "Vuln Intel",
  description: "Next-gen vulnerability intelligence platform"
};

const themeInitScript = `(function(){try{var k='vip:theme';var t=localStorage.getItem(k);var r=document.documentElement;r.classList.remove('light','dark');r.classList.add(t==='light'?'light':'dark');}catch(e){document.documentElement.classList.add('dark');}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ru" className="dark" suppressHydrationWarning>
      <body>
        <Script id="vip-theme" strategy="beforeInteractive">
          {themeInitScript}
        </Script>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}


import "./globals.css";
import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import Script from "next/script";
import { Providers } from "./providers";

const sans = IBM_Plex_Sans({
  subsets: ["latin", "cyrillic"],
  weight: ["400", "500", "600"],
  variable: "--font-sans",
  display: "swap"
});

const mono = IBM_Plex_Mono({
  subsets: ["latin", "cyrillic"],
  weight: ["400", "500"],
  variable: "--font-mono",
  display: "swap"
});

export const metadata: Metadata = {
  title: "VulnControl",
  description: "Vulnerability Management Platform",
  applicationName: "VulnControl",
  icons: {
    icon: [{ url: "/icon", type: "image/png" }]
  }
};

const themeInitScript = `(function(){try{var k='vip:theme';var t=localStorage.getItem(k);var r=document.documentElement;r.classList.remove('light','dark');r.classList.add(t==='light'?'light':'dark');}catch(e){document.documentElement.classList.add('dark');}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ru" className={`dark ${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <body className={`${sans.className} font-sans`}>
        <Script id="vip-theme" strategy="beforeInteractive">
          {themeInitScript}
        </Script>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}


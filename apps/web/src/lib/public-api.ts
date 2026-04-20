/** База публичного API для вызовов из браузера (CORS). Должна совпадать с UPSTREAM/NEXT_PUBLIC. */
export function getPublicApiBase(): string {
  const b = process.env.NEXT_PUBLIC_API_BASE?.trim();
  if (b) return b.replace(/\/+$/, "");
  if (typeof window !== "undefined") {
    const { protocol, hostname } = window.location;
    if (hostname === "localhost" || hostname === "127.0.0.1") {
      return `${protocol}//127.0.0.1:4001/api`;
    }
  }
  throw new Error("Задайте NEXT_PUBLIC_API_BASE (например http://127.0.0.1:4001/api)");
}

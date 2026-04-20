const ACCESS = "vip:access";
const REFRESH = "vip:refresh";

export function getStoredAccessToken(): string | null {
  if (typeof sessionStorage === "undefined") return null;
  return sessionStorage.getItem(ACCESS);
}

export function getStoredRefreshToken(): string | null {
  if (typeof sessionStorage === "undefined") return null;
  return sessionStorage.getItem(REFRESH);
}

export function setStoredTokens(access: string, refresh: string): void {
  sessionStorage.setItem(ACCESS, access);
  sessionStorage.setItem(REFRESH, refresh);
}

export function clearStoredTokens(): void {
  sessionStorage.removeItem(ACCESS);
  sessionStorage.removeItem(REFRESH);
}

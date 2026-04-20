/** Прокси Next → Nest: пробрасываем Bearer от клиента (sessionStorage → fetch → BFF). */
export function forwardAuthHeaders(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  const auth = req.headers.get("authorization");
  if (auth) out.authorization = auth;
  return out;
}

import { proxyToUpstream } from "../../_proxy";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return proxyToUpstream(req, `/asv/assets/${encodeURIComponent(id)}`);
}

export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return proxyToUpstream(req, `/asv/assets/${encodeURIComponent(id)}`);
}


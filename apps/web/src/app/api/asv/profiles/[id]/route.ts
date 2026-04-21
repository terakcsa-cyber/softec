import { proxyToUpstream } from "../../_proxy";

export async function PATCH(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  return proxyToUpstream(req, `/asv/profiles/${encodeURIComponent(id)}`);
}


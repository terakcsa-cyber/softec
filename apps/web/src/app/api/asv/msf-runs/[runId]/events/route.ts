import { proxyToUpstream } from "../../../_proxy";

export async function GET(req: Request, ctx: { params: Promise<{ runId: string }> }) {
  const { runId } = await ctx.params;
  return proxyToUpstream(req, `/asv/msf-runs/${runId}/events`);
}


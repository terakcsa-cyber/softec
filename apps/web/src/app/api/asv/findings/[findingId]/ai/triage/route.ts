import { proxyToUpstream } from "../../../../_proxy";

export async function GET(req: Request, ctx: { params: Promise<{ findingId: string }> }) {
  const { findingId } = await ctx.params;
  return proxyToUpstream(req, `/asv/findings/${encodeURIComponent(findingId)}/ai/triage`);
}

export async function POST(req: Request, ctx: { params: Promise<{ findingId: string }> }) {
  const { findingId } = await ctx.params;
  return proxyToUpstream(req, `/asv/findings/${encodeURIComponent(findingId)}/ai/triage`);
}


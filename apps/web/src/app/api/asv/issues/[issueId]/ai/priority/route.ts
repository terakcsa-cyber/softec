import { proxyToUpstream } from "../../../../_proxy";

export async function GET(req: Request, ctx: { params: Promise<{ issueId: string }> }) {
  const { issueId } = await ctx.params;
  return proxyToUpstream(req, `/asv/issues/${encodeURIComponent(issueId)}/ai/priority`);
}

export async function POST(req: Request, ctx: { params: Promise<{ issueId: string }> }) {
  const { issueId } = await ctx.params;
  return proxyToUpstream(req, `/asv/issues/${encodeURIComponent(issueId)}/ai/priority`);
}


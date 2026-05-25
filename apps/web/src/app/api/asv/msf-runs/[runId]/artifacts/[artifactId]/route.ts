import { proxyToUpstream } from "../../../../_proxy";

export async function GET(req: Request, ctx: { params: Promise<{ runId: string; artifactId: string }> }) {
  const { runId, artifactId } = await ctx.params;
  return proxyToUpstream(req, `/asv/msf-runs/${runId}/artifacts/${artifactId}`);
}


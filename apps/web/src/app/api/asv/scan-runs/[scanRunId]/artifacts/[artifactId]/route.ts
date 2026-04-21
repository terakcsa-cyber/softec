import { proxyToUpstream } from "../../../../_proxy";

export async function GET(
  req: Request,
  ctx: { params: Promise<{ scanRunId: string; artifactId: string }> }
) {
  const { scanRunId, artifactId } = await ctx.params;
  return proxyToUpstream(
    req,
    `/asv/scan-runs/${encodeURIComponent(scanRunId)}/artifacts/${encodeURIComponent(artifactId)}`
  );
}


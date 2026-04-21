import { proxyToUpstream } from "../../../_proxy";

export async function GET(req: Request, ctx: { params: Promise<{ templateId: string }> }) {
  const { templateId } = await ctx.params;
  return proxyToUpstream(req, `/asv/nuclei/templates/${encodeURIComponent(templateId)}`);
}


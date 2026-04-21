import { proxyToUpstream } from "../_proxy";

export async function GET(req: Request) {
  return proxyToUpstream(req, "/asv/scan-runs");
}

export async function POST(req: Request) {
  return proxyToUpstream(req, "/asv/scan-runs");
}


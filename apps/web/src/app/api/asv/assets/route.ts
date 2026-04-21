import { proxyToUpstream } from "../_proxy";

export async function GET(req: Request) {
  return proxyToUpstream(req, "/asv/assets");
}

export async function POST(req: Request) {
  return proxyToUpstream(req, "/asv/assets");
}


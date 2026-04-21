import { proxyToUpstream } from "../../_proxy";

export async function GET(req: Request) {
  return proxyToUpstream(req, "/asv/observations/http");
}


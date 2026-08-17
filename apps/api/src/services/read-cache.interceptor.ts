import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from "@nestjs/common";
import { from, lastValueFrom, type Observable } from "rxjs";
import { DataRevisionService, revisionSliceForPath } from "./data-revision.service.js";

function hasSearchQuery(url: string): boolean {
  const qIndex = url.indexOf("?");
  if (qIndex < 0) return false;
  return Boolean(new URLSearchParams(url.slice(qIndex)).get("q")?.trim());
}

@Injectable()
export class ReadCacheInterceptor implements NestInterceptor {
  constructor(private readonly revisions: DataRevisionService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest<{ method?: string; originalUrl?: string; url?: string }>();
    if (req.method !== "GET") return next.handle();
    const url = String(req.originalUrl || req.url || "");
    if (hasSearchQuery(url)) return next.handle();
    const slice = revisionSliceForPath(url);
    if (!slice || this.revisions.ttlSec() <= 0) return next.handle();
    return from(this.revisions.withSlice(slice, `http:${url}`, () => lastValueFrom(next.handle())));
  }
}

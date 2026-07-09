import { Controller, Get, Headers, Res, UnauthorizedException } from "@nestjs/common";
import { SkipThrottle } from "@nestjs/throttler";
import { getMetricsRegistry, renderMetrics } from "@vuln-intel/shared";
import type { Response } from "express";
import { Public } from "../auth/public.decorator.js";

@Controller("metrics")
@SkipThrottle()
export class MetricsController {
  @Public()
  @Get()
  async get(@Res() res: Response, @Headers("authorization") auth?: string) {
    const bearer = process.env.METRICS_BEARER?.trim();
    if (bearer) {
      if (auth?.trim() !== `Bearer ${bearer}`) {
        throw new UnauthorizedException();
      }
    }
    const body = await renderMetrics();
    res.setHeader("Content-Type", getMetricsRegistry().contentType);
    res.send(body);
  }
}

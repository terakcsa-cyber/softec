import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import http from "node:http";
import https from "node:https";
import { readFile } from "node:fs/promises";
import type { Duplex } from "node:stream";
import { URL } from "node:url";

export type LocalHttpsProxyInfo = {
  running: boolean;
  listenPort: number | null;
  upstream: string | null;
  publicUrl: string | null;
  message: string;
};

/**
 * Host-local HTTPS terminator for `pnpm dev` / API-without-Caddy:
 * terminates TLS with Settings-generated certs and reverse-proxies to the Next.js web.
 */
@Injectable()
export class LocalHttpsProxyService implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger(LocalHttpsProxyService.name);
  private server: https.Server | null = null;
  private listenPort: number | null = null;
  private upstream: string | null = null;

  async onModuleInit(): Promise<void> {
    if (process.env.WEB_TLS_LOCAL_PROXY === "false") return;
    // Docker Caddy path owns TLS when admin URL is set.
    if (process.env.TLS_PROXY_ADMIN_URL?.trim()) return;
    const cert = process.env.TLS_BOOT_CERT?.trim();
    const key = process.env.TLS_BOOT_KEY?.trim();
    // Boot is driven by WebTlsService after paths are known.
    void cert;
    void key;
  }

  async onModuleDestroy(): Promise<void> {
    await this.stop();
  }

  info(): LocalHttpsProxyInfo {
    const port = this.listenPort;
    const running = Boolean(this.server && port);
    return {
      running,
      listenPort: port,
      upstream: this.upstream,
      publicUrl: running && port ? `https://127.0.0.1:${port}` : null,
      message: running
        ? `Локальный HTTPS-прокси слушает :${port} → ${this.upstream}`
        : "Локальный HTTPS-прокси не запущен."
    };
  }

  async ensureListening(certPath: string, keyPath: string): Promise<LocalHttpsProxyInfo> {
    if (process.env.WEB_TLS_LOCAL_PROXY === "false") {
      return {
        running: false,
        listenPort: null,
        upstream: null,
        publicUrl: null,
        message: "Локальный HTTPS-прокси отключён (WEB_TLS_LOCAL_PROXY=false)."
      };
    }

    const port = this.resolvePort();
    const upstream = this.resolveUpstream();
    const [cert, key] = await Promise.all([readFile(certPath), readFile(keyPath)]);

    await this.stop();

    const server = https.createServer({ cert, key }, (req, res) => {
      this.proxyHttp(req, res, upstream);
    });

    server.on("upgrade", (req, socket, head) => {
      this.proxyUpgrade(req, socket as Duplex, head, upstream);
    });

    await new Promise<void>((resolve, reject) => {
      const onErr = (err: Error) => {
        server.off("listening", onListen);
        reject(err);
      };
      const onListen = () => {
        server.off("error", onErr);
        resolve();
      };
      server.once("error", onErr);
      server.once("listening", onListen);
      server.listen(port, "0.0.0.0");
    });

    this.server = server;
    this.listenPort = port;
    this.upstream = upstream;
    this.log.log(`Local HTTPS proxy listening on :${port} → ${upstream}`);
    return this.info();
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    this.listenPort = null;
    this.upstream = null;
    if (!server) return;
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      // Force-resolve if close hangs on open keep-alives.
      setTimeout(() => resolve(), 1500).unref?.();
    });
  }

  private resolvePort(): number {
    const n = Number(process.env.WEB_TLS_LOCAL_PORT ?? process.env.WEB_TLS_PUBLISHED_PORT ?? 3443);
    if (!Number.isFinite(n) || n < 1 || n > 65535) return 3443;
    return Math.floor(n);
  }

  private resolveUpstream(): string {
    const raw =
      process.env.WEB_TLS_UPSTREAM?.trim() ||
      process.env.PUBLIC_WEB_ORIGIN?.trim() ||
      `http://127.0.0.1:${process.env.WEB_PORT?.trim() || "3001"}`;
    try {
      const u = new URL(raw);
      if (u.protocol === "https:") {
        // Avoid TLS loops — upstream must be the plain Next.js HTTP port.
        return `http://${u.hostname}:${u.port || "3001"}`;
      }
      return u.origin;
    } catch {
      return "http://127.0.0.1:3001";
    }
  }

  private proxyHttp(req: http.IncomingMessage, res: http.ServerResponse, upstream: string): void {
    const target = new URL(upstream);
    const headers = { ...req.headers, host: target.host };
    const proxyReq = http.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || 80,
        path: req.url,
        method: req.method,
        headers
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
        proxyRes.pipe(res);
      }
    );
    proxyReq.on("error", (err) => {
      this.log.warn(`HTTPS proxy upstream error: ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
      }
      res.end("Bad gateway: web upstream unreachable");
    });
    req.pipe(proxyReq);
  }

  private proxyUpgrade(
    req: http.IncomingMessage,
    socket: Duplex,
    head: Buffer,
    upstream: string
  ): void {
    const target = new URL(upstream);
    const headers = { ...req.headers, host: target.host };
    const proxyReq = http.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 80,
      path: req.url,
      method: req.method,
      headers
    });
    proxyReq.on("upgrade", (proxyRes, proxySocket, proxyHead) => {
      socket.write(
        `HTTP/1.1 101 Switching Protocols\r\n` +
          Object.entries(proxyRes.headers)
            .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
            .join("\r\n") +
          `\r\n\r\n`
      );
      if (proxyHead?.length) socket.write(proxyHead);
      if (head?.length) proxySocket.write(head);
      proxySocket.pipe(socket);
      socket.pipe(proxySocket);
    });
    proxyReq.on("error", (err) => {
      this.log.warn(`HTTPS proxy upgrade error: ${err.message}`);
      socket.destroy();
    });
    proxyReq.end();
  }
}

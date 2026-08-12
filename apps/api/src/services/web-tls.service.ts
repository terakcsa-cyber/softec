import { BadRequestException, Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { spawn } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import {
  access,
  chmod,
  mkdir,
  readFile,
  rename,
  unlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { LocalHttpsProxyService } from "./local-https-proxy.service.js";
import { LetsEncryptCertbotService } from "./letsencrypt-certbot.service.js";

export type WebTlsStatus = {
  configured: boolean;
  selfSigned: boolean;
  commonName: string | null;
  subjectAltNames: string[];
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  fingerprintSha256: string | null;
  certsDir: string;
  certPresent: boolean;
  keyPresent: boolean;
  proxy: {
    adminUrlConfigured: boolean;
    reachable: boolean;
    reloadedAtGenerate: boolean | null;
    message: string;
  };
  localProxy: {
    running: boolean;
    listenPort: number | null;
    publicUrl: string | null;
    message: string;
  };
  applied: boolean;
  httpsUrl: string | null;
  publishedTlsPort: string | null;
  defaultDomain: string;
  defaultTargetIsIp: boolean;
  warningRu: string;
  issuer: "letsencrypt" | "selfsigned" | "unknown";
  certbotAvailable: boolean;
  certbotSupportsIpCertificates: boolean;
  acmeWebroot: string;
  letsEncryptReadyHintRu: string;
  ipHttpsHintRu: string;
};

export type WebTlsGenerateResult = WebTlsStatus & {
  generated: true;
  domain: string;
  days: number;
  messageRu: string;
};

const SELF_SIGNED_WARNING_RU =
  "Сертификат самоподписанный: браузеры покажут предупреждение, пока вы не добавите его в доверенные (или не замените на сертификат от УЦ / Let's Encrypt на внешнем reverse proxy).";

@Injectable()
export class WebTlsService implements OnModuleInit {
  private readonly log = new Logger(WebTlsService.name);

  constructor(
    private readonly localProxy: LocalHttpsProxyService,
    private readonly certbot: LetsEncryptCertbotService
  ) {}

  async onModuleInit(): Promise<void> {
    try {
      if ((await this.exists(this.certPath())) && (await this.exists(this.keyPath()))) {
        await this.applyToRuntime({ preferDocker: true });
      }
    } catch (err) {
      this.log.warn(`TLS boot apply skipped: ${err instanceof Error ? err.message : String(err)}`);
    }
    this.scheduleLetsEncryptAutoRenew();
  }

  /**
   * Periodic check: renew Let's Encrypt when days remaining is below threshold.
   * Domain certs default &lt; 30 days; IP/shortlived (~6d) default &lt; 2 days.
   * Disable with LETSENCRYPT_AUTO_RENEW=false.
   */
  private scheduleLetsEncryptAutoRenew(): void {
    if (process.env.LETSENCRYPT_AUTO_RENEW === "false") return;
    const intervalMs = Math.max(
      60 * 60_000,
      Number(process.env.LETSENCRYPT_AUTO_RENEW_INTERVAL_MS ?? 24 * 60 * 60_000)
    );
    const initialDelayMs = Math.max(30_000, Number(process.env.LETSENCRYPT_AUTO_RENEW_INITIAL_MS ?? 120_000));

    const tick = async () => {
      try {
        const status = await this.getStatus();
        if (status.issuer !== "letsencrypt") return;
        const meta = await this.certbot.readIssuerMeta(this.certsDir());
        const shortlived = meta.shortlived || this.certbot.isIpLiteral(meta.domain ?? "");
        const thresholdDays = Math.max(
          1,
          Number(
            shortlived
              ? (process.env.LETSENCRYPT_IP_RENEW_DAYS ?? 2)
              : (process.env.LETSENCRYPT_RENEW_DAYS ?? 30)
          )
        );
        if (status.daysRemaining == null || status.daysRemaining >= thresholdDays) return;
        this.log.log(
          `LE auto-renew: daysRemaining=${status.daysRemaining} < ${thresholdDays} (shortlived=${shortlived}), running certbot renew`
        );
        await this.renewLetsEncrypt();
      } catch (err) {
        this.log.warn(`LE auto-renew skipped: ${err instanceof Error ? err.message : String(err)}`);
      }
    };

    setTimeout(() => {
      void tick();
      setInterval(() => void tick(), intervalMs);
    }, initialDelayMs);
  }

  certsDir(): string {
    const raw = process.env.TLS_CERTS_DIR?.trim();
    if (raw) return resolve(raw);
    return resolve(process.cwd(), "data", "tls-certs");
  }

  certPath(): string {
    return join(this.certsDir(), "cert.pem");
  }

  keyPath(): string {
    return join(this.certsDir(), "key.pem");
  }

  defaultDomain(): string {
    const fromEnv = process.env.TLS_DOMAIN?.trim();
    if (fromEnv) return fromEnv.replace(/^https?:\/\//i, "").split("/")[0]!.split(":")[0]!;
    const origin = process.env.PUBLIC_WEB_ORIGIN?.trim();
    if (origin) {
      try {
        const host = new URL(origin).hostname;
        if (host) return host;
      } catch {
        // ignore
      }
    }
    return "localhost";
  }

  async getStatus(opts?: { reloadedAtGenerate?: boolean | null }): Promise<WebTlsStatus> {
    const dir = this.certsDir();
    const certFile = this.certPath();
    const keyFile = this.keyPath();
    const certPresent = await this.exists(certFile);
    const keyPresent = await this.exists(keyFile);

    let commonName: string | null = null;
    let subjectAltNames: string[] = [];
    let validFrom: string | null = null;
    let validTo: string | null = null;
    let daysRemaining: number | null = null;
    let fingerprintSha256: string | null = null;
    let selfSigned = true;

    if (certPresent) {
      try {
        const pem = await readFile(certFile, "utf8");
        const x509 = new X509Certificate(pem);
        commonName = this.extractCn(x509.subject);
        subjectAltNames = this.parseSan(x509.subjectAltName);
        validFrom = new Date(x509.validFrom).toISOString();
        validTo = new Date(x509.validTo).toISOString();
        daysRemaining = Math.floor((new Date(x509.validTo).getTime() - Date.now()) / 86_400_000);
        fingerprintSha256 = createHash("sha256").update(x509.raw).digest("hex");
        selfSigned = x509.subject === x509.issuer;
      } catch (err) {
        this.log.warn(`Failed to parse TLS cert at ${certFile}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    const proxy = await this.probeProxy(opts?.reloadedAtGenerate ?? null);
    const localInfo = this.localProxy.info();
    const publishedTlsPort = process.env.WEB_TLS_PUBLISHED_PORT?.trim() || null;
    const applied = Boolean(proxy.reachable || proxy.reloadedAtGenerate || localInfo.running);
    const hostForUrl =
      this.pickHttpsHost(subjectAltNames, commonName) || this.defaultDomain();
    const httpsUrl = this.buildHttpsUrl({
      domain: hostForUrl,
      dockerReachable: proxy.reachable || Boolean(proxy.reloadedAtGenerate),
      publishedTlsPort,
      local: localInfo
    });

    const marker = await this.certbot.readIssuerMarker(dir);
    const issuer: "letsencrypt" | "selfsigned" | "unknown" = selfSigned
      ? "selfsigned"
      : marker === "letsencrypt"
        ? "letsencrypt"
        : marker;
    const certbotAvailable = await this.certbot.isCertbotAvailable();
    const certbotSupportsIpCertificates = await this.certbot.supportsIpCertificates();
    const defaultDomain = this.defaultDomain();
    const defaultTargetIsIp = this.certbot.isIpLiteral(defaultDomain);
    const warningRu =
      issuer === "letsencrypt"
        ? "Сертификат Let's Encrypt (доверенный УЦ). Обновление: кнопка «Обновить LE» или авто-renew по сроку."
        : SELF_SIGNED_WARNING_RU;

    return {
      configured: certPresent && keyPresent,
      selfSigned,
      commonName,
      subjectAltNames,
      validFrom,
      validTo,
      daysRemaining,
      fingerprintSha256,
      certsDir: dir,
      certPresent,
      keyPresent,
      proxy,
      localProxy: {
        running: localInfo.running,
        listenPort: localInfo.listenPort,
        publicUrl: localInfo.publicUrl,
        message: localInfo.message
      },
      applied,
      httpsUrl,
      publishedTlsPort,
      defaultDomain,
      defaultTargetIsIp,
      warningRu,
      issuer,
      certbotAvailable,
      certbotSupportsIpCertificates,
      acmeWebroot: this.certbot.webrootDir(),
      letsEncryptReadyHintRu: certbotSupportsIpCertificates
        ? "Let's Encrypt (certbot HTTP-01): публичный домен (DNS) или публичный IP + порт 80 (tls-proxy отдаёт /.well-known/acme-challenge/). Для IP нужен shortlived-профиль (~6 дней). Email обязателен."
        : "Let's Encrypt через certbot (HTTP-01): публичный DNS на этот хост + порт 80. Для голого IP в этом образе certbot слишком старый — используйте самоподписанный с IP в SAN.",
      ipHttpsHintRu:
        "Доступ по IP без DNS: укажите IPv4/IPv6 и нажмите «HTTPS для IP (самоподписанный)». Браузер покажет предупреждение — это ожидаемо. Опционально: LE IP (shortlived ~6 дн.), если certbot ≥ 5.4 и порт 80 доступен с интернета."
    };
  }

  async generateAndApply(input: {
    domain?: string;
    days?: number;
    extraSans?: string[];
  }): Promise<WebTlsGenerateResult> {
    const domain = this.normalizeHost(input.domain?.trim() || this.defaultDomain());
    const days = this.clampDays(input.days);
    const extra = (input.extraSans ?? [])
      .map((s) => this.normalizeHost(String(s)))
      .filter(Boolean);

    const sans = this.uniqueSans([domain, "localhost", "127.0.0.1", "::1", ...extra]);
    const dir = this.certsDir();
    await mkdir(dir, { recursive: true, mode: 0o700 });

    const certFile = this.certPath();
    const keyFile = this.keyPath();
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const tmpDir = join(tmpdir(), `vuln-tls-${stamp}`);
    await mkdir(tmpDir, { recursive: true, mode: 0o700 });

    const tmpKey = join(tmpDir, "key.pem");
    const tmpCert = join(tmpDir, "cert.pem");
    const tmpCfg = join(tmpDir, "openssl.cnf");
    const cn = this.opensslCn(domain);

    try {
      await writeFile(tmpCfg, this.opensslConfig(cn, sans), { mode: 0o600 });
      await this.runOpenssl([
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        String(days),
        "-nodes",
        "-keyout",
        tmpKey,
        "-out",
        tmpCert,
        "-config",
        tmpCfg,
        "-extensions",
        "v3_req"
      ]);

      const stagingKey = join(dir, `.key.pem.${stamp}`);
      const stagingCert = join(dir, `.cert.pem.${stamp}`);
      await this.copyFile(tmpKey, stagingKey);
      await this.copyFile(tmpCert, stagingCert);
      await chmod(stagingKey, 0o600);
      await chmod(stagingCert, 0o644);
      await rename(stagingKey, keyFile);
      await rename(stagingCert, certFile);
      await writeFile(
        join(dir, "issuer.json"),
        JSON.stringify(
          {
            issuer: "selfsigned",
            installedAt: new Date().toISOString(),
            domain,
            targetIsIp: this.certbot.isIpLiteral(domain)
          },
          null,
          2
        ),
        { mode: 0o644 }
      );

      this.log.log(`Generated TLS certificate for target=${domain} (days=${days}); private key not logged`);
    } finally {
      await this.safeUnlink(tmpKey);
      await this.safeUnlink(tmpCert);
      await this.safeUnlink(tmpCfg);
      await this.safeRmdir(tmpDir);
    }

    const apply = await this.applyToRuntime({ preferDocker: true });
    const status = await this.getStatus({ reloadedAtGenerate: apply.dockerReloaded });
    const url =
      status.httpsUrl ??
      this.buildHttpsUrl({
        domain,
        dockerReachable: true,
        publishedTlsPort: process.env.WEB_TLS_PUBLISHED_PORT?.trim() || null,
        local: this.localProxy.info()
      }) ??
      `https://${this.formatUrlHost(domain)}`;

    let messageRu: string;
    if (status.applied && url) {
      messageRu = this.certbot.isIpLiteral(domain)
        ? `Самоподписанный сертификат с SAN IP:${domain} создан и применён: откройте ${url}`
        : `Сертификат для «${domain}» создан и повешен на веб: откройте ${url}`;
    } else if (apply.local?.running && apply.local.publicUrl) {
      messageRu = `Сертификат для «${domain}» создан; локальный HTTPS-прокси: ${apply.local.publicUrl}`;
    } else {
      messageRu = `Сертификат сохранён в ${dir}, но HTTPS-прокси не удалось поднять (${apply.error ?? "нет слушателя"}). Проверьте openssl/порт ${process.env.WEB_TLS_LOCAL_PORT ?? 3443} или Docker tls-proxy.`;
    }

    return {
      ...status,
      generated: true,
      domain,
      days,
      httpsUrl: status.httpsUrl ?? url,
      messageRu: `${messageRu} ${SELF_SIGNED_WARNING_RU}`
    };
  }


  async issueLetsEncrypt(input: {
    domain?: string;
    email: string;
    staging?: boolean;
  }): Promise<WebTlsGenerateResult & { provider: "letsencrypt" }> {
    const domain = this.normalizeHost(input.domain?.trim() || this.defaultDomain());
    const email = this.certbot.normalizeEmail(input.email);
    const isIp = this.certbot.isIpLiteral(domain);
    if (isIp) {
      await this.certbot.assertIpIssuanceSupported();
    } else {
      this.certbot.assertPublicDomain(domain);
    }

    const issued = await this.certbot.issue({
      domain,
      email,
      staging: input.staging,
      ipAddress: isIp
    });
    await this.certbot.installIntoCertsDir({
      fullchainPath: issued.fullchainPath,
      privkeyPath: issued.privkeyPath,
      certsDir: this.certsDir(),
      domain: issued.domain,
      email: issued.email,
      staging: issued.staging,
      shortlived: issued.shortlived
    });

    const apply = await this.applyToRuntime({ preferDocker: true });
    const status = await this.getStatus({ reloadedAtGenerate: apply.dockerReloaded });
    const url =
      status.httpsUrl ?? `https://${this.formatUrlHost(domain)}${this.portSuffix(process.env.WEB_TLS_PUBLISHED_PORT)}`;
    const stagingNote = issued.staging ? " (staging CA — браузеры не будут доверять)." : "";
    const shortNote = issued.shortlived
      ? " Shortlived (~6 дней): авто-renew при сроке < LETSENCRYPT_IP_RENEW_DAYS (по умолчанию 2)."
      : "";
    const messageRu = status.applied
      ? `Let's Encrypt для «${domain}» выпущен через certbot и применён на веб: ${url}${stagingNote}${shortNote}`
      : `Let's Encrypt для «${domain}» выпущен и записан в ${this.certsDir()}, но прокси не поднялся (${apply.error ?? "нет слушателя"}).${stagingNote}${shortNote}`;

    return {
      ...status,
      generated: true,
      domain,
      days: status.daysRemaining ?? (issued.shortlived ? 6 : 90),
      provider: "letsencrypt",
      httpsUrl: status.httpsUrl ?? url,
      messageRu
    };
  }

  async renewLetsEncrypt(): Promise<WebTlsGenerateResult & { provider: "letsencrypt"; renewed: boolean }> {
    const meta = await this.certbot.readIssuerMeta(this.certsDir());
    if (meta.issuer !== "letsencrypt") {
      throw new BadRequestException(
        "На диске нет маркера Let's Encrypt. Сначала нажмите «Получить Let's Encrypt»."
      );
    }

    const renew = await this.certbot.renew();

    const preferred: string[] = [];
    if (meta.domain) preferred.push(meta.domain);
    if (meta.fullchainSource) {
      const fromPath = this.certbot.domainFromLivePath(meta.fullchainSource);
      if (fromPath) preferred.push(fromPath);
    }
    try {
      const pem = await readFile(this.certPath(), "utf8");
      const cn = this.extractCn(new X509Certificate(pem).subject);
      if (cn) preferred.push(cn);
    } catch {
      // ignore
    }
    preferred.push(this.defaultDomain());

    const live = await this.certbot.resolveLiveMaterial(preferred);
    if (!live) {
      throw new BadRequestException(
        "certbot renew завершился, но live/fullchain.pem не найден. Проверьте CERTBOT_CONFIG_DIR и повторный выпуск."
      );
    }

    await this.certbot.installIntoCertsDir({
      fullchainPath: live.fullchainPath,
      privkeyPath: live.privkeyPath,
      certsDir: this.certsDir(),
      domain: live.domain,
      email: meta.email ?? undefined,
      staging: meta.staging,
      shortlived: meta.shortlived || this.certbot.isIpLiteral(live.domain)
    });

    const apply = await this.applyToRuntime({ preferDocker: true });
    const status = await this.getStatus({ reloadedAtGenerate: apply.dockerReloaded });
    return {
      ...status,
      generated: true,
      domain: status.commonName || live.domain,
      days: status.daysRemaining ?? 0,
      provider: "letsencrypt",
      renewed: renew.renewed,
      messageRu: renew.renewed
        ? `Сертификат Let's Encrypt обновлён и применён${status.httpsUrl ? `: ${status.httpsUrl}` : "."}`
        : `certbot renew завершился без нового выпуска (ещё рано или уже актуален). Материал live/${live.domain} переустановлен. ${status.httpsUrl ?? ""}`
    };
  }

  private async applyToRuntime(opts: { preferDocker: boolean }): Promise<{
    dockerReloaded: boolean;
    local: ReturnType<LocalHttpsProxyService["info"]> | null;
    error?: string;
  }> {
    let dockerReloaded = false;
    if (opts.preferDocker) {
      dockerReloaded = await this.reloadProxy();
      if (dockerReloaded) {
        await this.localProxy.stop().catch(() => undefined);
        return { dockerReloaded: true, local: this.localProxy.info() };
      }
      const probe = await this.probeProxy(null);
      if (probe.reachable && process.env.TLS_CERTS_DIR?.trim()) {
        await this.localProxy.stop().catch(() => undefined);
        return { dockerReloaded: false, local: this.localProxy.info() };
      }
    }

    try {
      const local = await this.localProxy.ensureListening(this.certPath(), this.keyPath());
      return { dockerReloaded, local };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.log.warn(`Local HTTPS proxy failed: ${msg}`);
      return { dockerReloaded, local: this.localProxy.info(), error: msg };
    }
  }

  private buildHttpsUrl(opts: {
    domain: string;
    dockerReachable: boolean;
    publishedTlsPort: string | null;
    local: ReturnType<LocalHttpsProxyService["info"]>;
  }): string | null {
    const host = this.formatUrlHost(opts.domain || "localhost");
    if (opts.local.running && opts.local.listenPort) {
      return `https://${host}:${opts.local.listenPort}`;
    }
    if (opts.dockerReachable) {
      const port = opts.publishedTlsPort || "443";
      return port === "443" ? `https://${host}` : `https://${host}:${port}`;
    }
    return null;
  }

  private portSuffix(published: string | undefined): string {
    const port = published?.trim() || "443";
    return port === "443" ? "" : `:${port}`;
  }

  private formatUrlHost(host: string): string {
    const h = host.trim();
    if (!h) return "localhost";
    if (this.certbot.isIpv6Literal(h)) return `[${h}]`;
    return h;
  }

  /** Prefer an IP SAN when present so https://x.x.x.x matches the cert. */
  private pickHttpsHost(sans: string[], cn: string | null): string | null {
    const ipv4 = sans.find((s) => this.certbot.isIpv4Literal(s) && s !== "127.0.0.1");
    if (ipv4) return ipv4;
    const ipv6 = sans.find((s) => this.certbot.isIpv6Literal(s) && s !== "::1");
    if (ipv6) return ipv6;
    if (cn && this.certbot.isIpLiteral(cn)) return cn;
    const dns = sans.find((s) => s && s !== "localhost" && !this.certbot.isIpLiteral(s));
    if (dns) return dns;
    return cn;
  }

  private normalizeHost(raw: string): string {
    let s = raw.trim();
    s = s.replace(/^https?:\/\//i, "");
    s = s.split("/")[0] ?? s;
    // Strip brackets for IPv6 URL form [::1]:443
    if (s.startsWith("[")) {
      const end = s.indexOf("]");
      if (end > 1) s = s.slice(1, end);
      else s = s.replace(/^\[|\]$/g, "");
    } else if (!this.looksLikeBareIpv6(s)) {
      // hostname:port or ipv4:port — drop port
      const colon = s.lastIndexOf(":");
      if (colon > -1 && /^\d+$/.test(s.slice(colon + 1))) {
        s = s.slice(0, colon);
      }
    }
    s = s.trim().toLowerCase();
    if (!s || s.length > 253) {
      throw new BadRequestException("Некорректный домен или IP-адрес");
    }
    if (this.certbot.isIpv4Literal(s)) {
      if (!this.certbot.isValidIpv4(s)) {
        throw new BadRequestException("Некорректный IPv4-адрес");
      }
      return s;
    }
    if (this.certbot.isIpv6Literal(s) || this.looksLikeBareIpv6(s)) {
      const normalized = this.certbot.normalizeIpv6(s);
      if (!normalized) {
        throw new BadRequestException("Некорректный IPv6-адрес");
      }
      return normalized;
    }
    if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$|^localhost$/i.test(s)) {
      throw new BadRequestException("Домен может содержать только буквы, цифры, точки и дефисы (или укажите IP)");
    }
    return s;
  }

  private looksLikeBareIpv6(s: string): boolean {
    if (!s.includes(":")) return false;
    // hostname:port or ipv4:port — not IPv6
    if (/^[a-z0-9.-]+:\d+$/i.test(s)) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(s)) return false;
    return true;
  }

  /** OpenSSL DN CN: avoid raw IPv6 colons breaking DN parsing. */
  private opensslCn(host: string): string {
    if (this.certbot.isIpv6Literal(host)) return "ip-address";
    return host;
  }

  private clampDays(raw: number | undefined): number {
    const n = typeof raw === "number" && Number.isFinite(raw) ? Math.floor(raw) : 825;
    if (n < 1 || n > 825) {
      throw new BadRequestException("Срок действия сертификата: от 1 до 825 дней");
    }
    return n;
  }

  private uniqueSans(list: string[]): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const item of list) {
      if (!item || seen.has(item)) continue;
      seen.add(item);
      out.push(item);
    }
    return out;
  }

  private opensslConfig(cn: string, sans: string[]): string {
    let dnsIdx = 0;
    let ipIdx = 0;
    const altLines: string[] = [];
    for (const name of sans) {
      if (this.certbot.isIpLiteral(name)) {
        ipIdx += 1;
        altLines.push(`IP.${ipIdx} = ${name}`);
      } else {
        dnsIdx += 1;
        altLines.push(`DNS.${dnsIdx} = ${name}`);
      }
    }
    return [
      "[req]",
      "default_bits = 2048",
      "prompt = no",
      "default_md = sha256",
      "distinguished_name = dn",
      "x509_extensions = v3_req",
      "",
      "[dn]",
      `CN = ${cn}`,
      "O = Vuln Intel Platform",
      "OU = Internal TLS",
      "",
      "[v3_req]",
      "basicConstraints = CA:FALSE",
      "keyUsage = digitalSignature, keyEncipherment",
      "extendedKeyUsage = serverAuth",
      "subjectAltName = @alt_names",
      "",
      "[alt_names]",
      ...altLines,
      ""
    ].join("\n");
  }

  private runOpenssl(args: string[]): Promise<void> {
    return new Promise((resolvePromise, reject) => {
      const child = spawn("openssl", args, {
        stdio: ["ignore", "pipe", "pipe"],
        env: process.env
      });
      let stderr = "";
      child.stderr?.on("data", (chunk: Buffer) => {
        stderr += chunk.toString("utf8");
      });
      child.on("error", (err) => {
        reject(
          new BadRequestException(
            `openssl недоступен (${err.message}). Установите OpenSSL или используйте Docker-образ API.`
          )
        );
      });
      child.on("close", (code) => {
        if (code === 0) {
          resolvePromise();
          return;
        }
        const safe = stderr.replace(/-----BEGIN[\s\S]*?-----END[^\n]*/g, "[redacted]").slice(0, 400);
        this.log.warn(`openssl exited ${code}: ${safe}`);
        reject(new BadRequestException(`Не удалось сгенерировать сертификат (openssl exit ${code})`));
      });
    });
  }

  private async reloadProxy(): Promise<boolean> {
    const admin = process.env.TLS_PROXY_ADMIN_URL?.trim().replace(/\/+$/, "");
    if (!admin) return false;
    // Path inside tls-proxy container (shared acme volume). Must match infra/tls-proxy/Caddyfile.
    const acmeRoot =
      process.env.TLS_PROXY_ACME_WEBROOT?.trim() ||
      "/var/www/certbot";
    const caddyfile = [
      "{",
      "\tadmin 0.0.0.0:2019",
      "\tauto_https off",
      "}",
      "",
      ":443 {",
      "\ttls /certs/cert.pem /certs/key.pem",
      "\tencode gzip",
      "\treverse_proxy web:3000",
      "}",
      "",
      ":80 {",
      "\thandle /.well-known/acme-challenge/* {",
      `\t\troot * ${acmeRoot}`,
      "\t\tfile_server",
      "\t}",
      "\thandle {",
      "\t\tredir https://{host}{uri} permanent",
      "\t}",
      "}",
      ""
    ].join("\n");

    try {
      const res = await fetch(`${admin}/load`, {
        method: "POST",
        headers: { "content-type": "text/caddyfile" },
        body: caddyfile,
        signal: AbortSignal.timeout(5_000)
      });
      if (!res.ok) {
        this.log.warn(`TLS proxy reload HTTP ${res.status}`);
        return false;
      }
      return true;
    } catch (err) {
      this.log.warn(`TLS proxy reload failed: ${err instanceof Error ? err.message : String(err)}`);
      return false;
    }
  }

  private async probeProxy(reloadedAtGenerate: boolean | null): Promise<WebTlsStatus["proxy"]> {
    const admin = process.env.TLS_PROXY_ADMIN_URL?.trim().replace(/\/+$/, "");
    if (!admin) {
      return {
        adminUrlConfigured: false,
        reachable: false,
        reloadedAtGenerate,
        message: "Docker tls-proxy не настроен — для pnpm dev используется встроенный HTTPS-прокси API."
      };
    }
    try {
      const res = await fetch(`${admin}/config/`, {
        method: "GET",
        signal: AbortSignal.timeout(3_000)
      });
      return {
        adminUrlConfigured: true,
        reachable: res.ok,
        reloadedAtGenerate,
        message: res.ok
          ? "TLS-прокси (Caddy) доступен."
          : `TLS-прокси ответил HTTP ${res.status}.`
      };
    } catch {
      return {
        adminUrlConfigured: true,
        reachable: false,
        reloadedAtGenerate,
        message: "TLS-прокси недоступен по TLS_PROXY_ADMIN_URL."
      };
    }
  }

  private extractCn(subject: string): string | null {
    const m = /(?:^|,)\s*CN\s*=\s*([^,]+)/i.exec(subject);
    return m?.[1]?.trim() || null;
  }

  private parseSan(san: string | undefined): string[] {
    if (!san) return [];
    return san
      .split(",")
      .map((p) => p.trim())
      .map((p) => p.replace(/^(DNS|IP Address|IP):/i, "").trim())
      .filter(Boolean);
  }

  private async exists(path: string): Promise<boolean> {
    try {
      await access(path);
      return true;
    } catch {
      return false;
    }
  }

  private async copyFile(from: string, to: string): Promise<void> {
    const buf = await readFile(from);
    await mkdir(dirname(to), { recursive: true });
    await writeFile(to, buf, { mode: 0o600 });
  }

  private async safeUnlink(path: string): Promise<void> {
    try {
      await unlink(path);
    } catch {
      // ignore
    }
  }

  private async safeRmdir(path: string): Promise<void> {
    try {
      const { rmdir } = await import("node:fs/promises");
      await rmdir(path);
    } catch {
      // ignore
    }
  }
}

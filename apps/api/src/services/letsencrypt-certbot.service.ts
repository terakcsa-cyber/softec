import { BadRequestException, Injectable, Logger } from "@nestjs/common";
import { spawn } from "node:child_process";
import { access, chmod, copyFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

export type CertbotIssueResult = {
  domain: string;
  email: string;
  staging: boolean;
  liveDir: string;
  fullchainPath: string;
  privkeyPath: string;
};

/**
 * Runs certbot HTTP-01 (webroot) and materializes fullchain/privkey paths.
 * Requires public DNS + port 80 serving `/.well-known/acme-challenge/` from TLS_ACME_WEBROOT.
 */
@Injectable()
export class LetsEncryptCertbotService {
  private readonly log = new Logger(LetsEncryptCertbotService.name);

  webrootDir(): string {
    const raw = process.env.TLS_ACME_WEBROOT?.trim();
    if (raw) return resolve(raw);
    return resolve(process.cwd(), "data", "acme-webroot");
  }

  configDir(): string {
    const raw = process.env.CERTBOT_CONFIG_DIR?.trim();
    if (raw) return resolve(raw);
    return resolve(process.cwd(), "data", "letsencrypt");
  }

  workDir(): string {
    const raw = process.env.CERTBOT_WORK_DIR?.trim();
    if (raw) return resolve(raw);
    return join(this.configDir(), "work");
  }

  logsDir(): string {
    const raw = process.env.CERTBOT_LOGS_DIR?.trim();
    if (raw) return resolve(raw);
    return join(this.configDir(), "logs");
  }

  async isCertbotAvailable(): Promise<boolean> {
    try {
      await this.run(["--version"], { timeoutMs: 8_000 });
      return true;
    } catch {
      return false;
    }
  }

  normalizeEmail(raw: string): string {
    const email = raw.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new BadRequestException("Укажите корректный email для Let's Encrypt (регистрация ACME-аккаунта).");
    }
    return email;
  }

  assertPublicDomain(domain: string): void {
    const d = domain.trim().toLowerCase();
    if (!d || d === "localhost" || d.endsWith(".local") || d.endsWith(".internal")) {
      throw new BadRequestException(
        "Let's Encrypt не выдаёт сертификаты на localhost. Нужен публичный домен (A/AAAA → этот сервер)."
      );
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(d)) {
      throw new BadRequestException("Let's Encrypt HTTP-01 не поддерживает голый IP — нужен доменное имя.");
    }
  }

  async issue(input: {
    domain: string;
    email: string;
    staging?: boolean;
  }): Promise<CertbotIssueResult> {
    const domain = input.domain.trim().toLowerCase();
    const email = this.normalizeEmail(input.email);
    this.assertPublicDomain(domain);

    const staging =
      input.staging === true ||
      process.env.LETSENCRYPT_STAGING === "1" ||
      process.env.LETSENCRYPT_STAGING === "true";

    const webroot = this.webrootDir();
    const configDir = this.configDir();
    const workDir = this.workDir();
    const logsDir = this.logsDir();
    await mkdir(join(webroot, ".well-known", "acme-challenge"), { recursive: true, mode: 0o755 });
    await mkdir(configDir, { recursive: true, mode: 0o700 });
    await mkdir(workDir, { recursive: true, mode: 0o700 });
    await mkdir(logsDir, { recursive: true, mode: 0o700 });

    const available = await this.isCertbotAvailable();
    if (!available) {
      throw new BadRequestException(
        "certbot не установлен в окружении API. В Docker-образе API он должен быть (apk add certbot); локально: brew install certbot."
      );
    }

    const args = [
      "certonly",
      "--webroot",
      "-w",
      webroot,
      "-d",
      domain,
      "--email",
      email,
      "--agree-tos",
      "--non-interactive",
      "--keep-until-expiring",
      "--config-dir",
      configDir,
      "--work-dir",
      workDir,
      "--logs-dir",
      logsDir,
      "--preferred-challenges",
      "http"
    ];
    if (staging) args.push("--staging");

    this.log.log(`Starting certbot for ${domain} (staging=${staging}); email/key material not logged beyond account email domain`);
    try {
      await this.run(args, { timeoutMs: 180_000 });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new BadRequestException(this.friendlyCertbotError(msg, domain));
    }

    const liveDir = join(configDir, "live", domain);
    const fullchainPath = join(liveDir, "fullchain.pem");
    const privkeyPath = join(liveDir, "privkey.pem");
    await access(fullchainPath);
    await access(privkeyPath);

    return { domain, email, staging, liveDir, fullchainPath, privkeyPath };
  }

  async renew(): Promise<{ renewed: boolean; output: string }> {
    const available = await this.isCertbotAvailable();
    if (!available) return { renewed: false, output: "certbot missing" };
    // Do not force --staging here: certbot renew uses each lineage's renewal config.
    const args = [
      "renew",
      "--webroot",
      "-w",
      this.webrootDir(),
      "--non-interactive",
      "--config-dir",
      this.configDir(),
      "--work-dir",
      this.workDir(),
      "--logs-dir",
      this.logsDir(),
      "--preferred-challenges",
      "http"
    ];
    try {
      const output = await this.run(args, { timeoutMs: 180_000 });
      const renewed = /Congratulations|successfully renewed|new certificate/i.test(output);
      return { renewed, output: output.slice(0, 2000) };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new BadRequestException(`certbot renew не удался: ${msg.slice(0, 800)}`);
    }
  }

  async installIntoCertsDir(opts: {
    fullchainPath: string;
    privkeyPath: string;
    certsDir: string;
    domain?: string;
    email?: string;
    staging?: boolean;
  }): Promise<{ certPath: string; keyPath: string }> {
    const dir = opts.certsDir;
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const stamp = `${Date.now()}`;
    const stagingCert = join(dir, `.cert.pem.${stamp}`);
    const stagingKey = join(dir, `.key.pem.${stamp}`);
    const certPath = join(dir, "cert.pem");
    const keyPath = join(dir, "key.pem");

    await copyFile(opts.fullchainPath, stagingCert);
    await copyFile(opts.privkeyPath, stagingKey);
    await chmod(stagingKey, 0o600);
    await chmod(stagingCert, 0o644);
    await rename(stagingCert, certPath);
    await rename(stagingKey, keyPath);

    const domainFromPath = this.domainFromLivePath(opts.fullchainPath);
    // Marker for UI / renew logic
    await writeFile(
      join(dir, "issuer.json"),
      JSON.stringify(
        {
          issuer: "letsencrypt",
          installedAt: new Date().toISOString(),
          domain: opts.domain?.trim().toLowerCase() || domainFromPath || undefined,
          email: opts.email?.trim().toLowerCase() || undefined,
          staging: opts.staging === true,
          fullchainSource: opts.fullchainPath
        },
        null,
        2
      ),
      { mode: 0o644 }
    );

    return { certPath, keyPath };
  }

  async readIssuerMarker(certsDir: string): Promise<"letsencrypt" | "selfsigned" | "unknown"> {
    const meta = await this.readIssuerMeta(certsDir);
    return meta.issuer;
  }

  async readIssuerMeta(certsDir: string): Promise<{
    issuer: "letsencrypt" | "selfsigned" | "unknown";
    domain: string | null;
    email: string | null;
    staging: boolean;
    fullchainSource: string | null;
  }> {
    try {
      const raw = await readFile(join(certsDir, "issuer.json"), "utf8");
      const j = JSON.parse(raw) as {
        issuer?: string;
        domain?: string;
        email?: string;
        staging?: boolean;
        fullchainSource?: string;
      };
      const issuer =
        j.issuer === "letsencrypt" ? "letsencrypt" : j.issuer === "selfsigned" ? "selfsigned" : "unknown";
      return {
        issuer,
        domain: typeof j.domain === "string" && j.domain.trim() ? j.domain.trim().toLowerCase() : null,
        email: typeof j.email === "string" && j.email.trim() ? j.email.trim().toLowerCase() : null,
        staging: j.staging === true,
        fullchainSource: typeof j.fullchainSource === "string" ? j.fullchainSource : null
      };
    } catch {
      return { issuer: "unknown", domain: null, email: null, staging: false, fullchainSource: null };
    }
  }

  /** Prefer explicit domains, else first readable certbot live/<domain> material. */
  async resolveLiveMaterial(preferredDomains: string[] = []): Promise<{
    domain: string;
    fullchainPath: string;
    privkeyPath: string;
  } | null> {
    const candidates: string[] = [];
    for (const d of preferredDomains) {
      const n = d?.trim().toLowerCase();
      if (n) candidates.push(n);
    }

    const configDir = this.configDir();
    const liveRoot = join(configDir, "live");
    try {
      const { readdir } = await import("node:fs/promises");
      const entries = await readdir(liveRoot, { withFileTypes: true });
      for (const e of entries) {
        if (!e.isDirectory() || e.name.startsWith(".")) continue;
        candidates.push(e.name.toLowerCase());
      }
    } catch {
      // no live dir yet
    }

    const seen = new Set<string>();
    for (const domain of candidates) {
      if (!domain || seen.has(domain)) continue;
      seen.add(domain);
      const fullchainPath = join(liveRoot, domain, "fullchain.pem");
      const privkeyPath = join(liveRoot, domain, "privkey.pem");
      try {
        await access(fullchainPath);
        await access(privkeyPath);
        return { domain, fullchainPath, privkeyPath };
      } catch {
        // try next
      }
    }
    return null;
  }

  domainFromLivePath(fullchainPath: string): string | null {
    // .../live/<domain>/fullchain.pem
    const parts = fullchainPath.replace(/\\/g, "/").split("/");
    const liveIdx = parts.lastIndexOf("live");
    if (liveIdx >= 0 && parts[liveIdx + 1]) return parts[liveIdx + 1]!.toLowerCase();
    return null;
  }

  private friendlyCertbotError(raw: string, domain: string): string {
    const t = raw.toLowerCase();
    if (t.includes("too many certificates") || t.includes("rate limit")) {
      return `Let's Encrypt rate limit для «${domain}». Подождите или используйте LETSENCRYPT_STAGING=true для теста.`;
    }
    if (t.includes("nxdomain") || t.includes("no valid a records") || t.includes("dns problem")) {
      return `DNS: домен «${domain}» не резолвится на этот сервер. Проверьте A/AAAA запись.`;
    }
    if (
      t.includes("connection refused") ||
      t.includes("timeout") ||
      t.includes("unauthorized") ||
      t.includes("invalid response") ||
      t.includes("404")
    ) {
      return `HTTP-01 не прошёл для «${domain}»: Let's Encrypt должен достучаться до http://${domain}/.well-known/acme-challenge/ (порт 80, tls-proxy webroot).`;
    }
    if (t.includes("certbot: command not found") || t.includes("enoent")) {
      return "certbot не найден в PATH контейнера/хоста API.";
    }
    return `certbot не смог выпустить сертификат для «${domain}»: ${raw.slice(0, 700)}`;
  }

  private run(args: string[], opts: { timeoutMs: number }): Promise<string> {
    return new Promise((resolvePromise, reject) => {
      const child = spawn("certbot", args, {
        stdio: ["ignore", "pipe", "pipe"],
        env: process.env
      });
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        child.kill("SIGTERM");
        reject(new Error(`certbot timeout after ${opts.timeoutMs}ms`));
      }, opts.timeoutMs);
      child.stdout?.on("data", (c: Buffer) => {
        stdout += c.toString("utf8");
      });
      child.stderr?.on("data", (c: Buffer) => {
        stderr += c.toString("utf8");
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        const out = `${stdout}\n${stderr}`.trim();
        if (code === 0) {
          resolvePromise(out);
          return;
        }
        reject(new Error(out || `certbot exit ${code}`));
      });
    });
  }
}

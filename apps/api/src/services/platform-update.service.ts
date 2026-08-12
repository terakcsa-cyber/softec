import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  ServiceUnavailableException
} from "@nestjs/common";
import { spawn } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { constants as fsConstants } from "node:fs";

export type UpdateCommitInfo = {
  sha: string;
  shortSha: string;
  subject: string;
  date: string | null;
};

export type PlatformUpdateJob = {
  phase:
    | "idle"
    | "preflight"
    | "backup"
    | "fetch"
    | "pull"
    | "build"
    | "restart"
    | "done"
    | "failed"
    | "starting";
  progressRu: string;
  errorRu: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  updatedAt: string | null;
  pid: number | null;
};

export type PlatformUpdateStatus = {
  current: {
    sha: string | null;
    shortSha: string | null;
    branch: string | null;
    tag: string | null;
    versionLabel: string;
    source: "env" | "git" | "unknown";
  };
  remote: {
    url: string | null;
    branch: string;
    sha: string | null;
    shortSha: string | null;
  };
  updateAvailable: boolean;
  commitsAhead: UpdateCommitInfo[];
  commitsAheadCount: number;
  apply: {
    enabled: boolean;
    allowed: boolean;
    mode: "compose-helper" | "host-script" | "unavailable";
    blockersRu: string[];
  };
  job: PlatformUpdateJob | null;
  checkedAt: string | null;
  safetyNotesRu: string[];
  config: {
    repoDir: string | null;
    hostRepoPath: string | null;
    branch: string;
    envFile: string;
    composeFile: string;
    backupBeforeApply: boolean;
  };
};

type JobFile = {
  phase?: string;
  progressRu?: string;
  errorRu?: string | null;
  startedAt?: string | null;
  finishedAt?: string | null;
  updatedAt?: string | null;
  pid?: number | null;
};

@Injectable()
export class PlatformUpdateService {
  private readonly log = new Logger(PlatformUpdateService.name);
  private lastCheckedAt: string | null = null;
  private lastCheck: PlatformUpdateStatus | null = null;
  private applyLockUntil = 0;

  async getStatus(): Promise<PlatformUpdateStatus> {
    if (this.lastCheck && this.lastCheckedAt) {
      const job = await this.readJob();
      return { ...this.lastCheck, job };
    }
    return this.check({ soft: true });
  }

  async check(opts?: { soft?: boolean }): Promise<PlatformUpdateStatus> {
    const cfg = this.config();
    const safetyNotesRu = [
      "Volumes Postgres/Redis/RabbitMQ не удаляются (запрещён down -v / --fresh).",
      "Файлы .env и секреты не перезаписываются.",
      "Применение только fast-forward (без force-push и переписывания истории).",
      "Перед apply по умолчанию делается pg_dump в backups/."
    ];

    const current = await this.resolveCurrent(cfg.repoDir);
    const branch = cfg.branch || current.branch || "main";
    const remoteUrl = await this.resolveRemoteUrl(cfg.repoDir, cfg.repoUrl);
    const blockers: string[] = [];
    let remoteSha: string | null = null;
    let commitsAhead: UpdateCommitInfo[] = [];

    if (!remoteUrl) {
      blockers.push(
        "Не задан remote URL. Укажите PLATFORM_UPDATE_REPO_URL или смонтируйте git-репозиторий (PLATFORM_REPO_DIR)."
      );
    }

    try {
      if (cfg.repoDir && (await this.isGitRepo(cfg.repoDir))) {
        await this.execCapture("git", ["-C", cfg.repoDir, "fetch", "--prune", "origin", branch], {
          timeoutMs: 120_000,
          allowFail: opts?.soft === true
        });
        remoteSha = (
          await this.execCapture("git", ["-C", cfg.repoDir, "rev-parse", `origin/${branch}`], {
            timeoutMs: 15_000,
            allowFail: true
          })
        )?.trim() || null;
        if (current.sha && remoteSha && current.sha !== remoteSha) {
          commitsAhead = await this.listCommitsAhead(cfg.repoDir, current.sha, `origin/${branch}`);
        }
      } else if (remoteUrl) {
        remoteSha = await this.lsRemoteSha(remoteUrl, branch);
        if (current.sha && remoteSha && current.sha !== remoteSha) {
          commitsAhead = [
            {
              sha: remoteSha,
              shortSha: remoteSha.slice(0, 7),
              subject: "Доступен новый коммит на remote (полный changelog недоступен без локального git checkout)",
              date: null
            }
          ];
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.log.warn(`Update check failed: ${msg}`);
      if (!opts?.soft) {
        throw new ServiceUnavailableException(`Не удалось проверить обновления: ${msg}`);
      }
      blockers.push(`Проверка remote не удалась: ${msg}`);
    }

    const updateAvailable = Boolean(current.sha && remoteSha && current.sha !== remoteSha);
    const applyGate = await this.evaluateApplyGate(cfg, blockers);

    const status: PlatformUpdateStatus = {
      current: {
        ...current,
        branch: current.branch ?? branch
      },
      remote: {
        url: remoteUrl,
        branch,
        sha: remoteSha,
        shortSha: remoteSha ? remoteSha.slice(0, 7) : null
      },
      updateAvailable,
      commitsAhead,
      commitsAheadCount: commitsAhead.length,
      apply: applyGate,
      job: await this.readJob(),
      checkedAt: new Date().toISOString(),
      safetyNotesRu,
      config: {
        repoDir: cfg.repoDir,
        hostRepoPath: cfg.hostRepoPath,
        branch,
        envFile: cfg.envFile,
        composeFile: cfg.composeFile,
        backupBeforeApply: cfg.backup
      }
    };

    this.lastCheck = status;
    this.lastCheckedAt = status.checkedAt;
    return status;
  }

  async apply(): Promise<PlatformUpdateStatus> {
    if (Date.now() < this.applyLockUntil) {
      throw new ConflictException("Обновление уже запущено. Дождитесь завершения.");
    }

    const status = await this.check();
    if (!status.apply.enabled) {
      throw new BadRequestException(
        "Автоприменение отключено. Задайте PLATFORM_UPDATE_APPLY_ENABLED=true и смонтируйте репозиторий (см. docs)."
      );
    }
    if (!status.apply.allowed) {
      throw new BadRequestException(
        status.apply.blockersRu.join(" ") || "Применение обновления сейчас небезопасно."
      );
    }
    if (!status.updateAvailable) {
      throw new BadRequestException("Обновлений нет — текущая версия совпадает с remote.");
    }

    const job = await this.readJob();
    if (job && !["idle", "done", "failed"].includes(job.phase)) {
      const ageMs = job.updatedAt ? Date.now() - Date.parse(job.updatedAt) : 0;
      if (Number.isFinite(ageMs) && ageMs < 30 * 60_000) {
        throw new ConflictException("Обновление уже выполняется. Обновите статус через минуту.");
      }
    }

    this.applyLockUntil = Date.now() + 15_000;
    await this.writeJob({
      phase: "starting",
      progressRu: "Запуск безопасного обновления…",
      errorRu: null,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      updatedAt: new Date().toISOString(),
      pid: null
    });

    try {
      if (status.apply.mode === "compose-helper") {
        await this.startComposeHelper();
      } else if (status.apply.mode === "host-script") {
        await this.startHostScript();
      } else {
        throw new BadRequestException("Нет безопасного режима применения.");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await this.writeJob({
        phase: "failed",
        progressRu: "Не удалось запустить обновление",
        errorRu: msg,
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        pid: null
      });
      throw err instanceof BadRequestException || err instanceof ConflictException
        ? err
        : new ServiceUnavailableException(msg);
    }

    return this.getStatus();
  }

  private config() {
    const repoDirRaw = process.env.PLATFORM_REPO_DIR?.trim();
    const repoDir = repoDirRaw ? resolve(repoDirRaw) : this.guessRepoDir();
    const hostRepoPath = process.env.PLATFORM_HOST_REPO_PATH?.trim() || null;
    const repoUrl = process.env.PLATFORM_UPDATE_REPO_URL?.trim() || null;
    const branch =
      process.env.PLATFORM_UPDATE_BRANCH?.trim() ||
      process.env.PLATFORM_UPDATE_CHANNEL?.trim() ||
      "";
    const envFile = process.env.PLATFORM_UPDATE_ENV_FILE?.trim() || ".env.production";
    const composeFile =
      process.env.PLATFORM_UPDATE_COMPOSE_FILE?.trim() || "infra/docker-compose.prod.yml";
    const applyEnabled = this.envTruthy(process.env.PLATFORM_UPDATE_APPLY_ENABLED);
    const backup = process.env.PLATFORM_UPDATE_BACKUP == null
      ? true
      : this.envTruthy(process.env.PLATFORM_UPDATE_BACKUP);
    const statusFile =
      process.env.PLATFORM_UPDATE_STATUS_FILE?.trim() ||
      (repoDir ? join(repoDir, "data", "platform-update-status.json") : null);

    return {
      repoDir,
      hostRepoPath,
      repoUrl,
      branch,
      envFile,
      composeFile,
      applyEnabled,
      backup,
      statusFile
    };
  }

  private guessRepoDir(): string | null {
    const candidates = [
      "/host-repo",
      resolve(process.cwd()),
      resolve(process.cwd(), ".."),
      resolve(process.cwd(), "../.."),
      resolve(process.cwd(), "../../..")
    ];
    for (const c of candidates) {
      if (existsSync(join(c, ".git"))) return c;
    }
    return existsSync("/host-repo") ? "/host-repo" : resolve(process.cwd());
  }

  private async evaluateApplyGate(
    cfg: ReturnType<PlatformUpdateService["config"]>,
    extraBlockers: string[]
  ): Promise<PlatformUpdateStatus["apply"]> {
    const blockersRu = [...extraBlockers];
    let mode: PlatformUpdateStatus["apply"]["mode"] = "unavailable";
    const enabled = cfg.applyEnabled;

    if (!enabled) {
      blockersRu.push(
        "Автоприменение выключено (PLATFORM_UPDATE_APPLY_ENABLED). Проверка доступна; apply на сервере: bash scripts/platform-update.sh"
      );
      return { enabled, allowed: false, mode, blockersRu: [...new Set(blockersRu)] };
    }

    const inDocker = await this.exists("/.dockerenv");
    const repoOk = cfg.repoDir != null && (await this.isGitRepo(cfg.repoDir));
    if (!repoOk) {
      blockersRu.push("PLATFORM_REPO_DIR не указывает на git checkout хоста.");
      return { enabled, allowed: false, mode, blockersRu: [...new Set(blockersRu)] };
    }

    const gateBlockers: string[] = [];
    if (await this.gitDirtyTracked(cfg.repoDir!)) {
      gateBlockers.push("Git working tree грязный — сначала уберите локальные правки.");
    }
    if (!(await this.exists(join(cfg.repoDir!, cfg.envFile)))) {
      gateBlockers.push(`Нет ${cfg.envFile} — секреты не создаём автоматически при обновлении.`);
    }
    if (!(await this.exists(join(cfg.repoDir!, cfg.composeFile)))) {
      gateBlockers.push(`Не найден ${cfg.composeFile}.`);
    }

    const dockerOk = await this.commandOk("docker", ["version"]);
    const composeOk = await this.commandOk("docker", ["compose", "version"]);
    if (inDocker) {
      if (!cfg.hostRepoPath) {
        gateBlockers.push(
          "В Docker для apply нужен PLATFORM_HOST_REPO_PATH (абсолютный путь к checkout на хосте)."
        );
      }
      if (!dockerOk) {
        gateBlockers.push(
          "В контейнере API нет docker CLI / docker.sock. Подключите infra/docker-compose.update-helper.yml."
        );
      }
      if (gateBlockers.length === 0 && cfg.hostRepoPath && dockerOk) {
        mode = "compose-helper";
      }
    } else if (composeOk) {
      if (gateBlockers.length === 0) mode = "host-script";
    } else {
      gateBlockers.push(
        "Локальный pnpm dev не поддерживает one-click apply. Используйте docker compose или scripts/platform-update.sh на сервере."
      );
    }

    blockersRu.push(...gateBlockers);
    const allowed = mode !== "unavailable" && gateBlockers.length === 0;
    return {
      enabled,
      allowed,
      mode: allowed ? mode : "unavailable",
      blockersRu: [...new Set(blockersRu)]
    };
  }

  private async resolveCurrent(repoDir: string | null): Promise<PlatformUpdateStatus["current"]> {
    const envSha = (process.env.PLATFORM_GIT_SHA || process.env.GIT_COMMIT || "").trim();
    if (envSha) {
      return {
        sha: envSha,
        shortSha: envSha.slice(0, 7),
        branch: process.env.PLATFORM_GIT_BRANCH?.trim() || null,
        tag: process.env.PLATFORM_GIT_TAG?.trim() || null,
        versionLabel: process.env.PLATFORM_GIT_TAG?.trim() || envSha.slice(0, 7),
        source: "env"
      };
    }

    if (repoDir && (await this.isGitRepo(repoDir))) {
      const sha = (await this.execCapture("git", ["-C", repoDir, "rev-parse", "HEAD"], { allowFail: true }))?.trim() || null;
      const branch =
        (await this.execCapture("git", ["-C", repoDir, "rev-parse", "--abbrev-ref", "HEAD"], {
          allowFail: true
        }))?.trim() || null;
      const tag =
        (await this.execCapture(
          "git",
          ["-C", repoDir, "describe", "--tags", "--exact-match"],
          { allowFail: true }
        ))?.trim() || null;
      if (sha) {
        return {
          sha,
          shortSha: sha.slice(0, 7),
          branch: branch === "HEAD" ? null : branch,
          tag,
          versionLabel: tag || sha.slice(0, 7),
          source: "git"
        };
      }
    }

    return {
      sha: null,
      shortSha: null,
      branch: null,
      tag: null,
      versionLabel: "unknown",
      source: "unknown"
    };
  }

  private async resolveRemoteUrl(repoDir: string | null, override: string | null): Promise<string | null> {
    if (override) return override;
    if (!repoDir || !(await this.isGitRepo(repoDir))) return null;
    const url = (
      await this.execCapture("git", ["-C", repoDir, "remote", "get-url", "origin"], { allowFail: true })
    )?.trim();
    return url || null;
  }

  private async lsRemoteSha(remoteUrl: string, branch: string): Promise<string | null> {
    const out = await this.execCapture("git", ["ls-remote", remoteUrl, `refs/heads/${branch}`], {
      timeoutMs: 60_000,
      allowFail: true
    });
    if (!out) return null;
    const line = out.split("\n").map((l) => l.trim()).find(Boolean);
    if (!line) return null;
    const sha = line.split(/\s+/)[0];
    return sha && /^[0-9a-f]{7,40}$/i.test(sha) ? sha : null;
  }

  private async listCommitsAhead(repoDir: string, fromSha: string, toRef: string): Promise<UpdateCommitInfo[]> {
    const out = await this.execCapture(
      "git",
      ["-C", repoDir, "log", "--format=%H\t%cI\t%s", `${fromSha}..${toRef}`],
      { allowFail: true, timeoutMs: 30_000 }
    );
    if (!out) return [];
    return out
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .slice(0, 30)
      .map((line) => {
        const [sha, date, ...rest] = line.split("\t");
        const subject = rest.join("\t") || "(no subject)";
        return {
          sha: sha!,
          shortSha: sha!.slice(0, 7),
          subject,
          date: date || null
        };
      });
  }

  private async startHostScript(): Promise<void> {
    const cfg = this.config();
    if (!cfg.repoDir) throw new BadRequestException("repoDir missing");
    const script = join(cfg.repoDir, "scripts", "platform-update.sh");
    if (!(await this.exists(script))) {
      throw new BadRequestException("scripts/platform-update.sh не найден");
    }

    const child = spawn("bash", [script], {
      cwd: cfg.repoDir,
      detached: true,
      stdio: "ignore",
      env: {
        ...process.env,
        PLATFORM_UPDATE_BRANCH: cfg.branch || process.env.PLATFORM_UPDATE_BRANCH || "",
        PLATFORM_UPDATE_ENV_FILE: cfg.envFile,
        PLATFORM_UPDATE_COMPOSE_FILE: cfg.composeFile,
        PLATFORM_UPDATE_BACKUP: cfg.backup ? "1" : "0",
        PLATFORM_UPDATE_STATUS_FILE: cfg.statusFile || join(cfg.repoDir, "data", "platform-update-status.json"),
        PLATFORM_UPDATE_ALLOW_WIPE: "0"
      }
    });
    child.unref();
    await this.writeJob({
      phase: "starting",
      progressRu: "Скрипт обновления запущен на хосте…",
      errorRu: null,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      updatedAt: new Date().toISOString(),
      pid: child.pid ?? null
    });
  }

  private async startComposeHelper(): Promise<void> {
    const cfg = this.config();
    const hostPath = cfg.hostRepoPath;
    if (!hostPath) throw new BadRequestException("PLATFORM_HOST_REPO_PATH required");

    // One-shot updater outside the stack so API/web rebuild does not kill the job.
    const name = "vuln-intel-platform-updater";
    await this.execCapture("docker", ["rm", "-f", name], { allowFail: true, timeoutMs: 30_000 });

    const args = [
      "run",
      "-d",
      "--rm",
      "--name",
      name,
      "-v",
      `${hostPath}:${hostPath}`,
      "-v",
      "/var/run/docker.sock:/var/run/docker.sock",
      "-w",
      hostPath,
      "-e",
      `PLATFORM_UPDATE_BRANCH=${cfg.branch || ""}`,
      "-e",
      `PLATFORM_UPDATE_ENV_FILE=${cfg.envFile}`,
      "-e",
      `PLATFORM_UPDATE_COMPOSE_FILE=${cfg.composeFile}`,
      "-e",
      `PLATFORM_UPDATE_BACKUP=${cfg.backup ? "1" : "0"}`,
      "-e",
      `PLATFORM_UPDATE_STATUS_FILE=${hostPath}/data/platform-update-status.json`,
      "-e",
      "PLATFORM_UPDATE_ALLOW_WIPE=0",
      "docker:27-cli",
      "sh",
      "-c",
      "apk add --no-cache git bash curl >/dev/null && bash scripts/platform-update.sh"
    ];

    const id = await this.execCapture("docker", args, { timeoutMs: 120_000 });
    this.log.log(`Started updater container: ${(id || "").trim()}`);
    await this.writeJob({
      phase: "starting",
      progressRu: "Запущен one-shot updater (отдельный контейнер)…",
      errorRu: null,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      updatedAt: new Date().toISOString(),
      pid: null
    });
  }

  private async readJob(): Promise<PlatformUpdateJob | null> {
    const cfg = this.config();
    const file = cfg.statusFile;
    if (!file || !(await this.exists(file))) {
      return {
        phase: "idle",
        progressRu: "Ожидание",
        errorRu: null,
        startedAt: null,
        finishedAt: null,
        updatedAt: null,
        pid: null
      };
    }
    try {
      const raw = await readFile(file, "utf8");
      const j = JSON.parse(raw) as JobFile;
      return {
        phase: (j.phase as PlatformUpdateJob["phase"]) || "idle",
        progressRu: typeof j.progressRu === "string" ? j.progressRu : "",
        errorRu: typeof j.errorRu === "string" ? j.errorRu : null,
        startedAt: typeof j.startedAt === "string" ? j.startedAt : null,
        finishedAt: typeof j.finishedAt === "string" ? j.finishedAt : null,
        updatedAt: typeof j.updatedAt === "string" ? j.updatedAt : null,
        pid: typeof j.pid === "number" ? j.pid : null
      };
    } catch {
      return null;
    }
  }

  private async writeJob(job: PlatformUpdateJob): Promise<void> {
    const cfg = this.config();
    const file = cfg.statusFile;
    if (!file) return;
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify(job, null, 2), "utf8");
  }

  private async isGitRepo(dir: string): Promise<boolean> {
    return this.exists(join(dir, ".git"));
  }

  private async gitDirtyTracked(repoDir: string): Promise<boolean> {
    const out = await this.execCapture("git", ["-C", repoDir, "status", "--porcelain", "--untracked-files=no"], {
      allowFail: true
    });
    return Boolean(out && out.trim());
  }

  private async exists(path: string): Promise<boolean> {
    try {
      await access(path, fsConstants.F_OK);
      return true;
    } catch {
      return false;
    }
  }

  private envTruthy(v: string | undefined): boolean {
    if (!v) return false;
    return ["1", "true", "yes", "on"].includes(v.trim().toLowerCase());
  }

  private async commandOk(cmd: string, args: string[]): Promise<boolean> {
    const out = await this.execCapture(cmd, args, { allowFail: true, timeoutMs: 10_000 });
    return out != null;
  }

  private execCapture(
    cmd: string,
    args: string[],
    opts?: { timeoutMs?: number; allowFail?: boolean }
  ): Promise<string | null> {
    const timeoutMs = opts?.timeoutMs ?? 60_000;
    return new Promise((resolvePromise, reject) => {
      const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        if (opts?.allowFail) resolvePromise(null);
        else reject(new Error(`Timeout: ${cmd} ${args.join(" ")}`));
      }, timeoutMs);

      child.stdout.on("data", (b: Buffer) => {
        stdout += b.toString("utf8");
      });
      child.stderr.on("data", (b: Buffer) => {
        stderr += b.toString("utf8");
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        if (opts?.allowFail) resolvePromise(null);
        else reject(err);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        if (code === 0) resolvePromise(stdout);
        else if (opts?.allowFail) resolvePromise(null);
        else reject(new Error(stderr.trim() || stdout.trim() || `${cmd} exited ${code}`));
      });
    });
  }
}

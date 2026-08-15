import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  ServiceUnavailableException
} from "@nestjs/common";
import { spawn } from "node:child_process";
import { access, mkdir, readFile, readdir, stat, statfs, unlink, writeFile } from "node:fs/promises";
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

export type DiskMountInfo = {
  path: string;
  label: string;
  totalBytes: number;
  usedBytes: number;
  freeBytes: number;
  usedRatio: number;
};

export type BackupFileInfo = {
  name: string;
  sizeBytes: number;
  mtime: string | null;
};

export type PlatformStorageStatus = {
  checkedAt: string;
  mounts: DiskMountInfo[];
  backups: {
    dir: string | null;
    files: BackupFileInfo[];
    totalBytes: number;
    keepDefault: number;
  };
  docker: {
    available: boolean;
    summaryRu: string | null;
    reclaimableRu: string | null;
  };
  notesRu: string[];
};

export type PlatformCleanupResult = {
  deleted: Array<{ name: string; sizeBytes: number }>;
  kept: Array<{ name: string; sizeBytes: number }>;
  freedBytes: number;
  dockerPruned: boolean;
  dockerPruneLog: string | null;
  storage: PlatformStorageStatus;
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
    if (this.lastCheck) {
      const job = await this.readJob();
      const cfg = this.config();
      // Refresh "current" from mounted git so UI doesn't stick on bake-time PLATFORM_GIT_SHA.
      const current = await this.resolveCurrent(cfg.repoDir);
      const updateAvailable = Boolean(
        current.sha && this.lastCheck.remote.sha && current.sha !== this.lastCheck.remote.sha
      );
      return { ...this.lastCheck, current, updateAvailable, job };
    }
    // Opening the page must not git-fetch: from the API container that often hangs on SSH/GitHub.
    return this.snapshot({ fetchRemote: false });
  }

  async getStorage(): Promise<PlatformStorageStatus> {
    const cfg = this.config();
    const keepDefault = this.backupKeepDefault();
    const notesRu: string[] = [
      "Очистка удаляет только старые *.sql.gz в backups/, оставляя N свежих.",
      "Volumes Postgres/Redis/RabbitMQ и файлы .env никогда не трогаются.",
      "Опциональный Docker prune — только dangling images и build cache, без -a и без volumes."
    ];

    const mounts: DiskMountInfo[] = [];
    const seen = new Set<string>();
    const candidates: Array<{ path: string; label: string }> = [
      { path: cfg.repoDir || process.cwd(), label: "Репозиторий / данные" },
      { path: cfg.statusFile ? dirname(cfg.statusFile) : join(process.cwd(), "data"), label: "data/" },
      { path: "/", label: "Корень ФС (контейнер/хост)" }
    ];
    for (const c of candidates) {
      const abs = resolve(c.path);
      if (seen.has(abs)) continue;
      seen.add(abs);
      const m = await this.readMount(abs, c.label);
      if (m) mounts.push(m);
    }

    const backupsDir = cfg.repoDir ? join(cfg.repoDir, "backups") : null;
    const backupFiles = backupsDir ? await this.listBackupFiles(backupsDir) : [];
    const backupTotal = backupFiles.reduce((n, f) => n + f.sizeBytes, 0);

    const dockerOk = await this.commandOk("docker", ["version"]);
    let summaryRu: string | null = null;
    let reclaimableRu: string | null = null;
    if (dockerOk) {
      const dfOut = await this.execCapture("docker", ["system", "df"], {
        allowFail: true,
        timeoutMs: 20_000
      });
      if (dfOut) {
        summaryRu = dfOut
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
          .slice(0, 6)
          .join(" · ");
        const reclaimLine = dfOut
          .split("\n")
          .map((l) => l.trim())
          .find((l) => /reclaimable/i.test(l) || /можно освободить/i.test(l));
        if (reclaimLine) reclaimableRu = reclaimLine;
      }
    } else {
      notesRu.push("Docker CLI недоступен в API — для prune подключите update-helper (docker.sock).");
    }

    return {
      checkedAt: new Date().toISOString(),
      mounts,
      backups: {
        dir: backupsDir,
        files: backupFiles,
        totalBytes: backupTotal,
        keepDefault
      },
      docker: {
        available: dockerOk,
        summaryRu,
        reclaimableRu
      },
      notesRu
    };
  }

  async cleanupStorage(opts?: {
    keepBackups?: number;
    pruneDocker?: boolean;
  }): Promise<PlatformCleanupResult> {
    const cfg = this.config();
    if (!cfg.repoDir) {
      throw new BadRequestException("Нет PLATFORM_REPO_DIR / git checkout — очистка backups недоступна.");
    }
    const backupsDir = join(cfg.repoDir, "backups");
    const keep = Math.max(1, Math.min(50, Math.floor(opts?.keepBackups ?? this.backupKeepDefault())));
    const files = await this.listBackupFiles(backupsDir);
    const keepSet = new Set(files.slice(0, keep).map((f) => f.name));
    const toDelete = files.filter((f) => !keepSet.has(f.name));

    const deleted: Array<{ name: string; sizeBytes: number }> = [];
    for (const f of toDelete) {
      const full = join(backupsDir, f.name);
      // Safety: only basename *.sql.gz inside backups/
      if (f.name.includes("/") || f.name.includes("\\") || f.name.includes("..")) continue;
      if (!/\.sql\.gz$/i.test(f.name)) continue;
      try {
        await unlink(full);
        deleted.push({ name: f.name, sizeBytes: f.sizeBytes });
      } catch (err) {
        this.log.warn(`Failed to delete backup ${f.name}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    let dockerPruned = false;
    let dockerPruneLog: string | null = null;
    if (opts?.pruneDocker) {
      const dockerOk = await this.commandOk("docker", ["version"]);
      if (!dockerOk) {
        throw new BadRequestException(
          "Docker CLI недоступен. Подключите infra/docker-compose.update-helper.yml для prune."
        );
      }
      const parts: string[] = [];
      // No `docker system prune -a`, no volumes — only dangling + builder cache.
      const img = await this.execCapture("docker", ["image", "prune", "-f"], {
        allowFail: true,
        timeoutMs: 120_000
      });
      if (img?.trim()) parts.push(img.trim());
      const builder = await this.execCapture("docker", ["builder", "prune", "-f"], {
        allowFail: true,
        timeoutMs: 180_000
      });
      if (builder?.trim()) parts.push(builder.trim());
      dockerPruned = true;
      dockerPruneLog = parts.join("\n") || "Docker prune выполнен (dangling images + builder cache).";
    }

    const storage = await this.getStorage();
    return {
      deleted,
      kept: files.filter((f) => keepSet.has(f.name)).map((f) => ({ name: f.name, sizeBytes: f.sizeBytes })),
      freedBytes: deleted.reduce((n, f) => n + f.sizeBytes, 0),
      dockerPruned,
      dockerPruneLog,
      storage
    };
  }

  private backupKeepDefault(): number {
    const raw = process.env.PLATFORM_UPDATE_BACKUP_KEEP?.trim();
    const n = raw ? Number(raw) : 3;
    if (!Number.isFinite(n)) return 3;
    return Math.max(1, Math.min(50, Math.floor(n)));
  }

  private async readMount(path: string, label: string): Promise<DiskMountInfo | null> {
    try {
      if (!(await this.exists(path))) return null;
      const s = await statfs(path);
      const bsize = Number(s.bsize) || 0;
      const blocks = Number(s.blocks) || 0;
      const bavail = Number(s.bavail) || 0;
      const totalBytes = bsize * blocks;
      const freeBytes = bsize * bavail;
      if (totalBytes <= 0) return null;
      const usedBytes = Math.max(0, totalBytes - freeBytes);
      return {
        path,
        label,
        totalBytes,
        usedBytes,
        freeBytes,
        usedRatio: usedBytes / totalBytes
      };
    } catch {
      return null;
    }
  }

  private async listBackupFiles(dir: string): Promise<BackupFileInfo[]> {
    if (!(await this.exists(dir))) return [];
    try {
      const names = await readdir(dir);
      const out: BackupFileInfo[] = [];
      for (const name of names) {
        if (!/^(pre_update_|vuln_intel_).+\.sql\.gz$/i.test(name)) continue;
        if (name.includes("..") || name.includes("/") || name.includes("\\")) continue;
        try {
          const st = await stat(join(dir, name));
          if (!st.isFile()) continue;
          out.push({
            name,
            sizeBytes: st.size,
            mtime: st.mtime?.toISOString?.() ?? null
          });
        } catch {
          // skip
        }
      }
      out.sort((a, b) => {
        const ta = a.mtime ? Date.parse(a.mtime) : 0;
        const tb = b.mtime ? Date.parse(b.mtime) : 0;
        return tb - ta;
      });
      return out;
    } catch {
      return [];
    }
  }

  async check(opts?: { soft?: boolean }): Promise<PlatformUpdateStatus> {
    return this.snapshot({ fetchRemote: opts?.soft !== true });
  }

  private async snapshot(opts?: { fetchRemote?: boolean }): Promise<PlatformUpdateStatus> {
    const fetchRemote = opts?.fetchRemote === true;
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
        if (fetchRemote) {
          await this.execCapture("git", ["-C", cfg.repoDir, "fetch", "--prune", "origin", branch], {
            timeoutMs: 20_000,
            allowFail: false
          });
        }
        remoteSha = (
          await this.execCapture("git", ["-C", cfg.repoDir, "rev-parse", `origin/${branch}`], {
            timeoutMs: 8_000,
            allowFail: true
          })
        )?.trim() || null;
        if (current.sha && remoteSha && current.sha !== remoteSha) {
          commitsAhead = await this.listCommitsAhead(cfg.repoDir, current.sha, `origin/${branch}`);
        }
      } else if (remoteUrl && fetchRemote) {
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
      if (fetchRemote) {
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
      checkedAt: fetchRemote ? new Date().toISOString() : this.lastCheckedAt,
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
    if (fetchRemote && status.checkedAt) this.lastCheckedAt = status.checkedAt;
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
    // Default ON in production images that mount /host-repo; still overridable via env=false.
    const applyEnabled =
      process.env.PLATFORM_UPDATE_APPLY_ENABLED == null
        ? true
        : this.envTruthy(process.env.PLATFORM_UPDATE_APPLY_ENABLED);
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

  /** Absolute host path for docker run -v (compose-helper). */
  private async resolveHostRepoPath(
    cfg: ReturnType<PlatformUpdateService["config"]>
  ): Promise<string | null> {
    if (cfg.hostRepoPath) return cfg.hostRepoPath;
    if (!(await this.exists("/.dockerenv"))) {
      return cfg.repoDir;
    }
    const dest = cfg.repoDir || "/host-repo";
    const cid = (process.env.HOSTNAME || "").trim();
    if (!cid) return null;
    const out = await this.execCapture(
      "docker",
      [
        "inspect",
        "-f",
        `{{range .Mounts}}{{if eq .Destination "${dest}"}}{{.Source}}{{end}}{{end}}`,
        cid
      ],
      { allowFail: true, timeoutMs: 4_000 }
    );
    const src = out?.split("\n").map((l) => l.trim()).find(Boolean) || null;
    return src && src.startsWith("/") ? src : null;
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
        "Автоприменение выключено (PLATFORM_UPDATE_APPLY_ENABLED=false). Проверка доступна; apply на сервере: bash scripts/platform-update.sh"
      );
      return { enabled, allowed: false, mode, blockersRu: [...new Set(blockersRu)] };
    }

    const inDocker = await this.exists("/.dockerenv");
    const repoOk = cfg.repoDir != null && (await this.isGitRepo(cfg.repoDir));
    if (!repoOk) {
      blockersRu.push(
        "Нет git checkout в контейнере (/host-repo). Пересоздайте api через обычный deploy: ./deploy.sh --yes --update (mount репозитория уже в docker-compose.prod.yml)."
      );
      return { enabled, allowed: false, mode, blockersRu: [...new Set(blockersRu)] };
    }

    const hostPath = await this.resolveHostRepoPath(cfg);
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
      if (!hostPath) {
        gateBlockers.push(
          "Не удалось определить путь checkout на хосте (mount /host-repo). Пересоздайте api: ./deploy.sh --yes --update"
        );
      }
      if (!dockerOk) {
        gateBlockers.push(
          "В контейнере API нет docker CLI / docker.sock. Пересоздайте api обычным deploy (sock уже в docker-compose.prod.yml)."
        );
      }
      if (gateBlockers.length === 0 && hostPath && dockerOk) {
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
    // Prefer live checkout (/host-repo). PLATFORM_GIT_SHA is bake-time and stays stale after apply
    // until the next image rebuild — that made UI show "update available" forever.
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
      timeoutMs: 20_000,
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
        PLATFORM_UPDATE_REPO_URL: cfg.repoUrl || process.env.PLATFORM_UPDATE_REPO_URL || "",
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
    const hostPath = await this.resolveHostRepoPath(cfg);
    if (!hostPath) {
      throw new BadRequestException(
        "Не удалось определить host path для /host-repo. Пересоздайте api: ./deploy.sh --yes --update"
      );
    }

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
      `PLATFORM_UPDATE_REPO_URL=${cfg.repoUrl || ""}`,
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
      "apk add --no-cache git bash curl openssh-client >/dev/null && bash scripts/platform-update.sh"
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
    const out = await this.execCapture(cmd, args, { allowFail: true, timeoutMs: 4_000 });
    return out != null;
  }

  private execCapture(
    cmd: string,
    args: string[],
    opts?: { timeoutMs?: number; allowFail?: boolean }
  ): Promise<string | null> {
    const timeoutMs = opts?.timeoutMs ?? 60_000;
    const env = { ...process.env };
    if (cmd === "git") {
      env.GIT_TERMINAL_PROMPT = "0";
      env.GIT_ASKPASS = env.GIT_ASKPASS || "true";
      env.GIT_SSH_COMMAND =
        env.GIT_SSH_COMMAND || "ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new";
    }
    return new Promise((resolvePromise, reject) => {
      const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], env });
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
